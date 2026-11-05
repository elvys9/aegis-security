use std::{sync::{Arc,mpsc},time::Duration};
#[test]
fn actual_filesystem_event_is_delivered_after_debounce() {
    let dir=tempfile::tempdir().unwrap();let (send,receive)=mpsc::channel();
    let guard=aegis_engine::watcher::start(vec![dir.path().to_path_buf()],Arc::new(move|path|{let _=send.send(path);})).unwrap();
    let file=dir.path().join("harmless.ps1");std::fs::write(&file,b"# watcher integration fixture; never executed").unwrap();
    let seen=receive.recv_timeout(Duration::from_secs(5)).expect("filesystem event");
    assert_eq!(seen,file);drop(guard);
}
