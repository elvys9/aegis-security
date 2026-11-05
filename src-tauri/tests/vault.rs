use aegis_engine::quarantine::Vault;
use sha2::{Digest,Sha256};
use std::{fs,io::{Read,Seek,SeekFrom,Write}};
fn digest(bytes:&[u8])->String {hex::encode(Sha256::digest(bytes))}
#[test]
fn roundtrip_restart_and_no_overwrite() {
    let temp=tempfile::tempdir().unwrap();let original=temp.path().join("sample.bin");
    let bytes=vec![0x5a;2*1024*1024+133];fs::write(&original,&bytes).unwrap();
    let root=temp.path().join("vault");let vault=Vault::open(&root).unwrap();
    let entry=vault.isolate(&original,&digest(&bytes),"test").unwrap();drop(vault);
    if original.exists(){fs::remove_file(&original).unwrap();}
    let vault=Vault::open(&root).unwrap();assert_eq!(vault.list().unwrap().len(),1);
    fs::write(&original,b"do not overwrite").unwrap();assert!(vault.restore(&entry.id).is_err());
    assert_eq!(fs::read(&original).unwrap(),b"do not overwrite");
    fs::remove_file(&original).unwrap();
    vault.restore(&entry.id).unwrap();assert_eq!(fs::read(&original).unwrap(),bytes);
    assert!(vault.list().unwrap().is_empty());
    let next=vault.isolate(&original,&digest(&bytes),"test").unwrap();
    vault.delete(&next.id).unwrap();assert!(vault.list().unwrap().is_empty());
}
#[test]
fn mismatch_never_removes_source_or_commits_container() {
    let temp=tempfile::tempdir().unwrap();let original=temp.path().join("sample.bin");fs::write(&original,b"test").unwrap();
    let vault=Vault::open(&temp.path().join("vault")).unwrap();
    assert!(vault.isolate(&original,&"0".repeat(64),"test").is_err());
    assert_eq!(fs::read(&original).unwrap(),b"test");assert!(vault.list().unwrap().is_empty());
}
#[test]
fn corrupted_and_truncated_content_is_never_published() {
    for truncate in [false,true] {
        let temp=tempfile::tempdir().unwrap();let original=temp.path().join("sample.bin");let bytes=vec![9;4096];fs::write(&original,&bytes).unwrap();
        let root=temp.path().join("vault");let vault=Vault::open(&root).unwrap();let entry=vault.isolate(&original,&digest(&bytes),"test").unwrap();
        if original.exists(){fs::remove_file(&original).unwrap();}
        let container=root.join(format!("{}.quar",entry.id));let mut file=fs::OpenOptions::new().read(true).write(true).open(container).unwrap();
        let size=file.metadata().unwrap().len();
        if truncate {file.set_len(size-1).unwrap();} else {file.seek(SeekFrom::End(-1)).unwrap();let mut byte=[0];file.read_exact(&mut byte).unwrap();byte[0]^=1;file.seek(SeekFrom::End(-1)).unwrap();file.write_all(&byte).unwrap();}
        drop(file);assert!(vault.restore(&entry.id).is_err());assert!(!original.exists());
    }
}
#[test]
fn identifier_cannot_escape_vault() {
    let temp=tempfile::tempdir().unwrap();let vault=Vault::open(&temp.path().join("vault")).unwrap();
    assert!(vault.restore("../master.key").is_err());assert!(vault.delete("../master.key").is_err());
}
#[cfg(windows)]
#[test]
fn downloaded_file_keeps_zone_identifier_after_restore() {
    let temp=tempfile::tempdir().unwrap(); let original=temp.path().join("download.bin");
    fs::write(&original,b"downloaded").unwrap();
    let zone=std::path::PathBuf::from(format!("{}:Zone.Identifier",original.display()));
    let marker=b"[ZoneTransfer]\r\nZoneId=3\r\n"; fs::write(&zone,marker).unwrap();
    let vault=Vault::open(&temp.path().join("vault")).unwrap();
    let entry=vault.isolate(&original,&digest(b"downloaded"),"test").unwrap();
    assert!(!original.exists());vault.restore(&entry.id).unwrap();
    assert_eq!(fs::read(zone).unwrap(),marker);
}
#[cfg(windows)]
#[test]
fn unsupported_named_stream_never_disappears() {
    let temp=tempfile::tempdir().unwrap();let original=temp.path().join("stream.bin");fs::write(&original,b"main").unwrap();
    let stream=std::path::PathBuf::from(format!("{}:important",original.display()));fs::write(&stream,b"keep").unwrap();
    let vault=Vault::open(&temp.path().join("vault")).unwrap();
    assert!(vault.isolate(&original,&digest(b"main"),"test").is_err());assert_eq!(fs::read(stream).unwrap(),b"keep");
}
#[test]
fn damaged_entry_does_not_hide_good_entries() {
    let temp=tempfile::tempdir().unwrap();let original=temp.path().join("file.bin");fs::write(&original,b"content").unwrap();
    let root=temp.path().join("vault");let vault=Vault::open(&root).unwrap();vault.isolate(&original,&digest(b"content"),"test").unwrap();
    fs::write(root.join(format!("{}.quar",uuid::Uuid::new_v4())),b"corrupted").unwrap();
    let entries=vault.list().unwrap();assert_eq!(entries.len(),2);assert_eq!(entries.iter().filter(|e| e.status=="damaged").count(),1);
}
#[test]
fn legacy_v01_container_remains_restorable() {
    let temp=tempfile::tempdir().unwrap();let original=temp.path().join("legacy.bin");fs::write(&original,b"legacy").unwrap();
    let root=temp.path().join("vault");let vault=Vault::open(&root).unwrap();let entry=vault.isolate(&original,&digest(b"legacy"),"test").unwrap();
    if original.exists(){fs::remove_file(&original).unwrap();}
    let container=root.join(format!("{}.quar",entry.id));let mut file=fs::OpenOptions::new().write(true).open(container).unwrap();file.write_all(b"AEGISV01").unwrap();drop(file);
    vault.restore(&entry.id).unwrap();assert_eq!(fs::read(original).unwrap(),b"legacy");
}
