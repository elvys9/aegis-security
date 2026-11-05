use crate::definitions::Definitions;
use anyhow::{bail, Context, Result};
use md5::Md5;
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{Read, Seek, SeekFrom}, path::{Path, PathBuf}, sync::atomic::{AtomicBool, Ordering}};

pub const BLOCK: usize = 64 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Section { pub name: String, pub offset: u64, pub size: u64, pub flags: u32, pub entropy: f64 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Analysis {
    pub sha256: String, pub md5: String, pub entropy: f64,
    pub anomalies: Vec<String>, pub malicious: bool, pub sections: Vec<Section>,
    pub size: u64, pub coverage: Vec<String>,
}
pub fn entropy(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 { return 0.0; }
    counts.iter().filter(|&&n| n != 0).map(|&n| { let p = n as f64 / total as f64; -p * p.log2() }).sum::<f64>().clamp(0.0, 8.0)
}
pub fn open_regular(path: &Path, delete_access: bool) -> Result<File> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() { bail!("Not a regular file"); }
    let mut options = OpenOptions::new(); options.read(true);
    #[cfg(windows)] {
        use std::os::windows::fs::{OpenOptionsExt, MetadataExt};
        // OPEN_REPARSE_POINT checks the object actually opened, not only its path.
        options.share_mode(1).custom_flags(0x00200000 | 0x08000000);
        if delete_access { options.access_mode(0x80000000 | 0x00010000); }
        let file = options.open(path)?;
        if file.metadata()?.file_attributes() & 0x400 != 0 { bail!("Reparse points are excluded"); }
        return Ok(file);
    }
    #[cfg(not(windows))] { let _ = delete_access; Ok(options.open(path)?) }
}
fn bytes(file: &mut File, at: u64, length: usize, size: u64) -> Result<Vec<u8>> {
    if length > 4096 || at > size || length as u64 > size - at { bail!("Truncated PE"); }
    let mut result = vec![0; length]; file.seek(SeekFrom::Start(at))?; file.read_exact(&mut result)?; Ok(result)
}
fn u16le(data: &[u8], at: usize) -> u16 { u16::from_le_bytes([data[at], data[at + 1]]) }
fn u32le(data: &[u8], at: usize) -> u32 { u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]) }
fn pe_sections(file: &mut File, size: u64) -> Result<Vec<Section>> {
    if size < 2 { return Ok(Vec::new()); }
    if bytes(file, 0, 2, size)? != b"MZ" { return Ok(Vec::new()); }
    let dos = bytes(file, 0, 64, size)?; let nt = u32le(&dos, 60) as u64;
    if nt < 64 { bail!("Invalid PE header offset"); }
    let coff = bytes(file, nt, 24, size)?;
    if &coff[..4] != b"PE\0\0" { bail!("Invalid PE signature"); }
    let count = u16le(&coff, 6) as usize; let optional = u16le(&coff, 20) as usize;
    if count == 0 || count > 96 || optional < 96 || optional > 4096 { bail!("Invalid PE dimensions"); }
    let opt = bytes(file, nt + 24, optional, size)?; let magic = u16le(&opt, 0);
    if magic != 0x10b && magic != 0x20b || magic == 0x20b && optional < 112 { bail!("Invalid optional header"); }
    let sa = u32le(&opt, 32) as u64; let fa = u32le(&opt, 36) as u64;
    let image = u32le(&opt, 56) as u64; let headers = u32le(&opt, 60) as u64;
    if !sa.is_power_of_two() || !fa.is_power_of_two() || sa < fa || fa > 65536 || (sa < 4096 && sa != fa) || (sa >= 4096 && fa < 512) || headers % fa != 0 || image % sa != 0 { bail!("Invalid PE alignment"); }
    let table = nt + 24 + optional as u64;
    if headers > size || headers > image || table + count as u64 * 40 > headers { bail!("Invalid PE section table"); }
    let mut sections: Vec<Section> = Vec::with_capacity(count);
    let mut virtual_ranges = Vec::new();
    for i in 0..count {
        let raw = bytes(file, table + i as u64 * 40, 40, size)?;
        let virtual_size = u32le(&raw, 8) as u64; let rva = u32le(&raw, 12) as u64;
        let length = u32le(&raw, 16) as u64; let offset = u32le(&raw, 20) as u64;
        let extent = virtual_size.max(length);
        if offset > size || length > size - offset || (length > 0 && offset < headers) || rva % sa != 0 || length % fa != 0 || (length > 0 && offset % fa != 0) || (sa < 4096 && length > 0 && offset != rva) || rva > image || extent > image - rva { bail!("PE section outside file/image"); }
        if sections.iter().any(|s| length > 0 && s.size > 0 && offset < s.offset + s.size && s.offset < offset + length) { bail!("Overlapping PE raw sections"); }
        if virtual_ranges.iter().any(|&(start, end)| extent > 0 && rva < end && start < rva + extent) { bail!("Overlapping PE virtual sections"); }
        virtual_ranges.push((rva, rva + extent));
        let name = raw[..8].iter().take_while(|&&c| c != 0).map(|&c| if c.is_ascii_graphic() { c as char } else { '.' }).collect();
        sections.push(Section { name, offset, size: length, flags: u32le(&raw, 36), entropy: 0.0 });
    }
    Ok(sections)
}
pub fn analyze_file(path: &Path, definitions: &Definitions, cancel: &AtomicBool) -> Result<Analysis> {
    if cancel.load(Ordering::Relaxed) { bail!("Cancelled"); }
    let mut file = open_regular(path, false).with_context(|| format!("Cannot read {}", path.display()))?;
    let initial = file.metadata()?; let size = initial.len();
    if size > u64::MAX / 8 { bail!("File exceeds cryptographic length limit"); }
    let mut coverage = vec![];
    let mut sections = match pe_sections(&mut file, size) { Ok(sections) => sections, Err(error) => { coverage.push(format!("PE incomplete: {error}")); vec![] } };
    file.seek(SeekFrom::Start(0))?;
    let mut global = [0u64; 256]; let mut section_counts = vec![[0u64; 256]; sections.len()];
    let mut sha = Sha256::new(); let mut md5 = Md5::new(); let mut at = 0u64; let mut buffer = [0u8; BLOCK];
    loop {
        if cancel.load(Ordering::Relaxed) { bail!("Cancelled"); }
        let n = file.read(&mut buffer)?; if n == 0 { break; }
        sha.update(&buffer[..n]); md5.update(&buffer[..n]); for &b in &buffer[..n] { global[b as usize] += 1; }
        for (section, counts) in sections.iter().zip(section_counts.iter_mut()) {
            let start = at.max(section.offset); let end = (at + n as u64).min(section.offset + section.size);
            if start < end { for &b in &buffer[(start - at) as usize..(end - at) as usize] { counts[b as usize] += 1; } }
        }
        at = at.checked_add(n as u64).context("Size overflow")?;
    }
    let after = file.metadata()?;
    if at != size || after.len() != size || after.modified().ok() != initial.modified().ok() { bail!("File changed during scan"); }
    let digest = hex::encode(sha.finalize()); let legacy = hex::encode(md5.finalize());
    let mut anomalies = Vec::new(); let mut malicious = false;
    if let Some(label) = definitions.manifest.hashes.get(&digest) { malicious = true; anomalies.push(format!("SHA-256: {label}")); }
    if !definitions.manifest.allow.contains(&digest) || malicious {
        for (section, counts) in sections.iter_mut().zip(section_counts.iter()) {
            section.entropy = entropy(counts, section.size);
            if section.flags & 0xa0000000 == 0xa0000000 { anomalies.push(format!("W^X Section {}", section.name)); }
            if section.flags & 0x20000000 != 0 && section.entropy > 7.2 { anomalies.push(format!("High entropy executable section {}", section.name)); }
        }
        #[cfg(feature="yara")] {
            if size <= 16 * 1024 * 1024 {
                file.seek(SeekFrom::Start(0))?; let mut data = Vec::with_capacity(size as usize); file.take(size + 1).read_to_end(&mut data)?;
                if data.len() as u64 != size { bail!("File changed before YARA"); }
                let mut scanner = yara_x::Scanner::new(&definitions.rules); scanner.set_timeout(std::time::Duration::from_secs(2));
                match scanner.scan(&data) { Ok(results) => { for rule in results.matching_rules() { anomalies.push(format!("YARA: {}", rule.identifier())); } }, Err(error) => coverage.push(format!("YARA incomplete: {error}")) }
            } else { coverage.push("YARA skipped: file exceeds 16 MiB inspection budget".into()); }
        }
        #[cfg(not(feature="yara"))] coverage.push("YARA disabled in this build; hashes and PE heuristics only".into());
    }
    Ok(Analysis { sha256: digest, md5: legacy, entropy: entropy(&global, size), anomalies, malicious, sections, size, coverage })
}
pub fn excluded(entry: &walkdir::DirEntry) -> bool {
    if entry.file_type().is_symlink() { return true; }
    let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
    if ["pagefile.sys", "hiberfil.sys", "swapfile.sys", "$recycle.bin", "system volume information"].contains(&name.as_str()) { return true; }
    #[cfg(windows)] { use std::os::windows::fs::MetadataExt; if entry.metadata().map(|m| m.file_attributes() & 0x400 != 0).unwrap_or(false) { return true; } }
    #[cfg(unix)] if [Path::new("/proc"), Path::new("/sys"), Path::new("/dev"), Path::new("/run")].iter().any(|p| entry.path() == *p) { return true; }
    false
}
pub fn quick_roots() -> Vec<PathBuf> {
    let mut roots = vec![std::env::temp_dir()];
    if let Some(path) = dirs::download_dir() { roots.push(path); }
    if let Some(path) = dirs::data_dir() { roots.push(path.clone()); #[cfg(windows)] roots.push(path.join("Microsoft/Windows/Start Menu/Programs/Startup")); }
    #[cfg(windows)] roots.extend(active_process_images());
    roots.sort(); roots.dedup(); roots.retain(|p| p.exists()); roots
}
#[cfg(windows)]
fn active_process_images() -> Vec<PathBuf> {
    use windows_sys::Win32::{Foundation::{CloseHandle, INVALID_HANDLE_VALUE}, System::{Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS}, Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION}}};
    use std::os::windows::ffi::OsStringExt;
    let mut paths = Vec::new();
    // On-disk images only: not process-memory scanning or injection detection.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE { return paths; }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed(); entry.dwSize = std::mem::size_of_val(&entry) as u32;
        let mut more = Process32FirstW(snapshot, &mut entry);
        while more != 0 && paths.len() < 4096 {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
            if !process.is_null() {
                let mut buffer = vec![0u16; 32768]; let mut length = buffer.len() as u32;
                if QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) != 0 { paths.push(PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length as usize]))); }
                CloseHandle(process);
            }
            more = Process32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
    }
    paths
}
