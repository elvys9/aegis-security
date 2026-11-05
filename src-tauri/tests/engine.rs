use aegis_engine::{definitions::Definitions, scanner::analyze_file};
use std::sync::atomic::AtomicBool;
#[test]
fn known_hashes_and_no_false_malware() {
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("plain.txt");
    std::fs::write(&path, b"abc").unwrap();
    let result = analyze_file(&path, &Definitions::bundled().unwrap(), &AtomicBool::new(false)).unwrap();
    assert_eq!(result.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(result.md5, "900150983cd24fb0d6963f7d28e17f72");
    assert!(!result.malicious); assert!((result.entropy - 3f64.log2()).abs() < 1e-10);
}
#[test]
fn cancelled_and_missing_files_are_errors() {
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("file.bin"); std::fs::write(&path, b"a").unwrap();
    let defs = Definitions::bundled().unwrap();
    assert!(analyze_file(&path, &defs, &AtomicBool::new(true)).is_err());
    assert!(analyze_file(&dir.path().join("missing"), &defs, &AtomicBool::new(false)).is_err());
}

fn pe_fixture() -> Vec<u8> {
    let mut data = vec![0u8; 1024];
    let put = |bytes: &mut [u8], at: usize, value: u32, count: usize| { bytes[at..at+count].copy_from_slice(&value.to_le_bytes()[..count]); };
    put(&mut data, 0, 0x5a4d, 2); put(&mut data, 60, 128, 4); put(&mut data, 128, 0x4550, 4);
    put(&mut data, 134, 1, 2); put(&mut data, 148, 224, 2); put(&mut data, 152, 0x10b, 2);
    put(&mut data, 184, 4096, 4); put(&mut data, 188, 512, 4); put(&mut data, 208, 8192, 4); put(&mut data, 212, 512, 4);
    data[376..381].copy_from_slice(b".text"); put(&mut data, 384, 512, 4); put(&mut data, 388, 4096, 4);
    put(&mut data, 392, 512, 4); put(&mut data, 396, 512, 4); put(&mut data, 412, 0xe0000020, 4);
    for (i, byte) in data[512..].iter_mut().enumerate() { *byte = (i % 256) as u8; } data
}
#[test]
fn pe_entropy_and_wx_are_evidence_not_malware_verdict() {
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("fixture.exe");
    std::fs::write(&path, pe_fixture()).unwrap();
    let result = analyze_file(&path, &Definitions::bundled().unwrap(), &AtomicBool::new(false)).unwrap();
    assert_eq!(result.sections.len(), 1); assert_eq!(result.sections[0].entropy, 8.0);
    assert_eq!(result.anomalies.len(), 2); assert!(!result.malicious);
}
#[test]
fn truncated_pe_preserves_hash_but_reports_incomplete_coverage() {
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("truncated.exe");
    let fixture = pe_fixture(); let defs = Definitions::bundled().unwrap();
    for size in [2, 63, 151, 375, 511, 1023] {
        std::fs::write(&path, &fixture[..size]).unwrap();
        let result = analyze_file(&path, &defs, &AtomicBool::new(false)).unwrap();
        assert!(result.coverage.iter().any(|s| s.starts_with("PE incomplete"))); assert!(!result.malicious);
    }
}
#[cfg(feature="yara")]
#[test]
fn harmless_fixture_runs_real_yara_rules() {
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("test.txt");
    std::fs::write(&path,b"AEGIS-ENGINE-SELF-TEST\n").unwrap();
    let result=analyze_file(&path,&Definitions::bundled().unwrap(),&AtomicBool::new(false)).unwrap();
    assert!(result.anomalies.iter().any(|s|s.contains("YARA: Aegis_Harmless_Self_Test")));
}
#[cfg(windows)]
#[test]
fn sharing_violation_is_reported_without_panic() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir=tempfile::tempdir().unwrap();let path=dir.path().join("locked.txt");std::fs::write(&path,b"locked").unwrap();
    let _locked=std::fs::OpenOptions::new().read(true).write(true).share_mode(0).open(&path).unwrap();
    assert!(analyze_file(&path,&Definitions::bundled().unwrap(),&AtomicBool::new(false)).is_err());
}
