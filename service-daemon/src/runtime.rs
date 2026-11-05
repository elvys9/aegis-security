use crate::{config::Config, security};
use crate::runtime_support::{append_bounded, interesting, within, PendingPaths, LOG_LIMIT};
use aegis_engine::{definitions::Definitions, scanner::analyze_file};
use anyhow::{Context, Result};
use crossbeam_channel::{bounded, RecvTimeoutError};
use notify::{RecursiveMode, Watcher};
use std::{fs::{File, OpenOptions}, path::{Path, PathBuf}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

fn log(file: &Mutex<File>, record: serde_json::Value) {
    if let Ok(mut file) = file.lock() {
        // A full disk must never cause destructive remediation or a panic.
        if let Ok(bytes) = serde_json::to_vec(&record) {
            let _ = append_bounded(&mut file, &bytes, LOG_LIMIT);
        }
    }
}

pub fn run(cancel: Arc<AtomicBool>) -> Result<()> {
    let executable = std::env::current_exe()?;
    let program_files = PathBuf::from(std::env::var_os("ProgramFiles").context("ProgramFiles absent")?);
    anyhow::ensure!(executable.starts_with(&program_files), "Service must be installed under ProgramFiles");
    for ancestor in executable.ancestors().take_while(|p| *p != program_files) { security::protected(ancestor)?; }
    let data = PathBuf::from(std::env::var_os("ProgramData").context("ProgramData absent")?).join("AegisSecurityService");
    security::protected(&data)?;
    let config_path = data.join("service.json");
    security::protected(&config_path)?;
    anyhow::ensure!(std::fs::metadata(&config_path)?.len() <= 65536, "Configuration too large");
    let config: Config = serde_json::from_slice(&std::fs::read(config_path)?)?;
    config.validate()?;
    for root in &config.roots { security::local_drive(root)?; security::reject_reparse(root)?; anyhow::ensure!(root.is_dir(), "Scan root is not a directory"); }
    let log_path = data.join("findings.jsonl");
    if log_path.exists() { security::protected(&log_path)?; }
    let logfile = Mutex::new(OpenOptions::new().create(true).write(true).truncate(false).open(&log_path)?);
    security::protected(&log_path)?;
    let definitions = Definitions::bundled()?;
    let (sender, receiver) = bounded::<PathBuf>(256);
    let pending = Arc::new(Mutex::new(PendingPaths::default()));
    let event_pending = pending.clone();
    let excluded_data = data.clone();
    let allowed_roots = config.roots.clone();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        if let Ok(event) = event {
            if matches!(event.kind, notify::EventKind::Create(_) | notify::EventKind::Modify(_)) {
                if let Ok(mut pending) = event_pending.lock() {
                    for path in event.paths {
                        if interesting(&path, &excluded_data) && allowed_roots.iter().any(|root| within(&path, root)) {
                            pending.changed(path, Instant::now());
                        }
                    }
                }
            }
        }
    })?;
    if config.watch { for root in &config.roots { watcher.watch(root, RecursiveMode::Recursive)?; } }
    log(&logfile, serde_json::json!({"event":"started","watch":config.watch,"workers":config.workers}));
    std::thread::scope(|scope| {
        for _ in 0..config.workers {
            let receiver = receiver.clone();
            let cancel = &cancel;
            let definitions = &definitions;
            let logfile = &logfile;
            scope.spawn(move || loop {
                if cancel.load(Ordering::Relaxed) { break; }
                let path = match receiver.recv_timeout(Duration::from_millis(250)) {
                    Ok(path) => path,
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(_) => break,
                };
                // Hold every parent without delete sharing for the complete
                // analysis, preventing rename/reparse replacement of ancestors.
                let Some(parent) = path.parent() else { continue; };
                let _parent_guards = match aegis_engine::platform::lock_parents(parent) {
                    Ok(guards) => guards,
                    Err(error) => {
                        log(logfile, serde_json::json!({"event":"path_lock_error","path":path,"error":error.to_string()}));
                        continue;
                    }
                };
                if security::reject_reparse(&path).is_err() { continue; }
                match analyze_file(&path, definitions, cancel) {
                    Ok(analysis) if analysis.malicious || !analysis.anomalies.is_empty() => log(logfile, serde_json::json!({"event":"finding","unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),"path":path,"sha256":analysis.sha256,"md5":analysis.md5,"entropy":analysis.entropy,"malicious":analysis.malicious,"anomalies":analysis.anomalies})),
                    Ok(_) => (),
                    Err(error) => log(logfile, serde_json::json!({"event":"scan_error","path":path,"error":error.to_string()})),
                }
            });
        }
        let mut next = Instant::now();
        while !cancel.load(Ordering::Relaxed) {
            if let Ok(mut pending) = pending.lock() {
                pending.dispatch(Instant::now(), |path| sender.try_send(path.to_owned()).is_ok());
            }
            if Instant::now() >= next {
                for root in &config.roots {
                    for entry in walkdir::WalkDir::new(root).follow_links(false).max_open(16).into_iter().filter_entry(|entry| !within(entry.path(), &data) && !is_reparse(entry.path())) {
                        if cancel.load(Ordering::Relaxed) { break; }
                        match entry {
                            Ok(entry) if entry.file_type().is_file() => {
                                let mut path = entry.into_path();
                                loop {
                                    if cancel.load(Ordering::Relaxed) { break; }
                                    match sender.send_timeout(path, Duration::from_millis(250)) {
                                        Ok(()) => break,
                                        Err(crossbeam_channel::SendTimeoutError::Timeout(value)) => path = value,
                                        Err(_) => break,
                                    }
                                }
                            }
                            Err(error) => log(&logfile, serde_json::json!({"event":"walk_error","error":error.to_string()})),
                            _ => (),
                        }
                    }
                }
                next = Instant::now() + Duration::from_secs(config.interval_seconds);
            }
            // Pending watcher paths debounce independently of full-scan timing.
            for _ in 0..10 { if cancel.load(Ordering::Relaxed) { break; } std::thread::sleep(Duration::from_millis(100)); }
        }
        drop(sender);
    });
    log(&logfile, serde_json::json!({"event":"stopped"}));
    Ok(())
}

fn is_reparse(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    std::fs::symlink_metadata(path).map(|m| m.file_attributes() & 0x400 != 0).unwrap_or(true)
}
