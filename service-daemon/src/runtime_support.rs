use std::{collections::HashMap, fs::File, io::{self, Seek, SeekFrom, Write}, path::{Path, PathBuf}, time::{Duration, Instant}};

pub const MAX_PENDING: usize = 256;
pub const LOG_LIMIT: u64 = 10 * 1024 * 1024;
const QUIET_PERIOD: Duration = Duration::from_secs(2);

/// Windows paths are compared by components, case-insensitively, so a sibling
/// named AegisSecurity-old is not accidentally excluded with the log directory.
pub fn within(path: &Path, directory: &Path) -> bool {
    let mut parts = path.components();
    directory.components().all(|expected| parts.next().is_some_and(|actual|
        actual.as_os_str().to_string_lossy().eq_ignore_ascii_case(&expected.as_os_str().to_string_lossy())))
}

pub fn interesting(path: &Path, excluded: &Path) -> bool {
    !within(path, excluded) && path.extension().and_then(|value| value.to_str()).is_some_and(|value|
        ["exe", "dll", "msi", "bat", "ps1"].iter().any(|extension| value.eq_ignore_ascii_case(extension)))
}

#[derive(Default)]
pub struct PendingPaths(HashMap<PathBuf, Instant>);
impl PendingPaths {
    pub fn changed(&mut self, path: PathBuf, now: Instant) {
        if self.0.contains_key(&path) || self.0.len() < MAX_PENDING { self.0.insert(path, now); }
    }
    pub fn dispatch(&mut self, now: Instant, mut enqueue: impl FnMut(&Path) -> bool) {
        self.0.retain(|path, changed| now.saturating_duration_since(*changed) < QUIET_PERIOD || !enqueue(path));
    }
}

/// Truncate the existing protected handle rather than renaming/reopening a path.
/// Old records are discarded at the cap; total on-disk size stays bounded.
pub fn append_bounded(file: &mut File, record: &[u8], limit: u64) -> io::Result<()> {
    let length = record.len() as u64 + 1;
    if length > limit { return Err(io::Error::new(io::ErrorKind::InvalidInput, "Log record exceeds limit")); }
    if file.metadata()?.len().saturating_add(length) > limit { file.set_len(0)?; }
    file.seek(SeekFrom::End(0))?;
    file.write_all(record)?;
    file.write_all(b"\n")?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_interesting_files_outside_log_directory() {
        let excluded = Path::new("C:/ProgramData/AegisSecurity");
        assert!(interesting(Path::new("C:/Users/test/NEW.EXE"), excluded));
        assert!(!interesting(Path::new("C:/Users/test/note.txt"), excluded));
        assert!(!interesting(Path::new("C:/PROGRAMDATA/AEGISSECURITY/test.exe"), excluded));
        assert!(interesting(Path::new("C:/ProgramData/AegisSecurity-old/test.exe"), excluded));
    }
    #[test]
    fn bursts_debounce_and_full_queue_retains_pending_path() {
        let start = Instant::now();
        let mut pending = PendingPaths::default();
        pending.changed("file.exe".into(), start);
        pending.changed("file.exe".into(), start + Duration::from_secs(1));
        pending.dispatch(start + Duration::from_secs(2), |_| panic!("Not quiet yet"));
        pending.dispatch(start + Duration::from_secs(3), |_| false);
        assert_eq!(pending.0.len(), 1);
        let mut count = 0;
        pending.dispatch(start + Duration::from_secs(4), |_| { count += 1; true });
        assert_eq!(count, 1);
        assert!(pending.0.is_empty());
    }
    #[test]
    fn pending_memory_is_bounded() {
        let mut pending = PendingPaths::default();
        for i in 0..MAX_PENDING * 2 { pending.changed(format!("{i}.exe").into(), Instant::now()); }
        assert_eq!(pending.0.len(), MAX_PENDING);
    }
    #[test]
    fn log_truncates_at_cap_and_rejects_oversize_records() {
        let path = std::env::temp_dir().join(format!("aegis-log-test-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let mut file = std::fs::OpenOptions::new().create_new(true).write(true).open(&path).unwrap();
        append_bounded(&mut file, b"first", 12).unwrap();
        append_bounded(&mut file, b"second", 12).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second\n");
        assert!(append_bounded(&mut file, &[0; 12], 12).is_err());
        assert!(file.metadata().unwrap().len() <= 12);
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
