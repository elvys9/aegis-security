use anyhow::{bail, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::{collections::HashMap, path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}}, thread, time::{Duration, Instant}};

pub struct WatcherHandle { stop: Arc<AtomicBool>, pub dropped: Arc<AtomicU64>, _watcher: RecommendedWatcher }
impl Drop for WatcherHandle { fn drop(&mut self) { self.stop.store(true, Ordering::Release); } }
pub fn interesting(path: &Path) -> bool {
    matches!(path.extension().and_then(|s| s.to_str()).map(str::to_ascii_lowercase).as_deref(), Some("exe" | "dll" | "msi" | "bat" | "ps1"))
}
pub fn roots() -> Vec<PathBuf> {
    let mut paths = vec![std::env::temp_dir()];
    if let Some(p) = dirs::download_dir() { paths.push(p); }
    if let Some(p) = dirs::desktop_dir() { paths.push(p); }
    paths.sort(); paths.dedup(); paths.retain(|p| p.is_dir()); paths
}
pub fn start(paths: Vec<PathBuf>, scan: Arc<dyn Fn(PathBuf) + Send + Sync>) -> Result<WatcherHandle> {
    let (sender, receiver) = crossbeam_channel::bounded::<notify::Result<Event>>(256);
    let dropped = Arc::new(AtomicU64::new(0)); let overflow = dropped.clone();
    let mut watcher = notify::recommended_watcher(move |event| { if sender.try_send(event).is_err() { overflow.fetch_add(1, Ordering::Relaxed); } })?;
    let mut watched = 0;
    for path in paths { if std::fs::symlink_metadata(&path).map(|m| m.file_type().is_symlink()).unwrap_or(true) { continue; } watcher.watch(&path, RecursiveMode::Recursive)?; watched += 1; }
    if watched == 0 { bail!("Nessuna cartella accessibile da monitorare"); }
    let stop = Arc::new(AtomicBool::new(false)); let stopping = stop.clone(); let count = dropped.clone();
    thread::Builder::new().name("aegis-watcher".into()).spawn(move || {
        let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
        while !stopping.load(Ordering::Acquire) {
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(event)) if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) => {
                    for path in event.paths { if interesting(&path) { if pending.len() < 1024 || pending.contains_key(&path) { pending.insert(path, Instant::now()); } else { count.fetch_add(1, Ordering::Relaxed); } } }
                }
                Ok(Err(_)) => { count.fetch_add(1, Ordering::Relaxed); }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                _ => {}
            }
            let ready: Vec<_> = pending.iter().filter(|(_, instant)| instant.elapsed() >= Duration::from_millis(750)).map(|(path, _)| path.clone()).take(16).collect();
            for path in ready { pending.remove(&path); if !stopping.load(Ordering::Acquire) { scan(path); } }
        }
    })?;
    Ok(WatcherHandle { stop, dropped, _watcher: watcher })
}
#[cfg(test)] mod tests { use super::*; #[test] fn extension_scope() { assert!(interesting(Path::new("test.PS1"))); assert!(!interesting(Path::new("photo.jpg"))); assert!(!interesting(Path::new("noextension"))); } }
