use crate::{definitions::Definitions, scanner, quarantine::{Vault, VaultEntry}, watcher, updater};
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::{collections::HashMap, path::PathBuf, sync::{Arc, Mutex, RwLock, atomic::{AtomicBool, AtomicU64, Ordering}}, time::{Duration, Instant}};
use tauri::{Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

#[derive(Clone, Serialize)]
struct Finding {
    id: String, name: String, path: String, sha256: String, md5: String, entropy: f64,
    anomalies: Vec<String>, coverage: Vec<String>, verdict: String, severity: String, status: String,
}
#[derive(Clone, Serialize)]
struct Progress { id: String, kind: String, status: String, files: u64, total: u64, rate: f64, path: String, errors: u64, incomplete: u64, found: u64 }
impl Default for Progress { fn default() -> Self { Self { id: String::new(), kind: "quick".into(), status: "idle".into(), files: 0, total: 0, rate: 0.0, path: String::new(), errors: 0, incomplete: 0, found: 0 } } }
#[derive(Clone, Serialize)]
struct Status { version: &'static str, watcher_enabled: bool, definitions_version: u64, update_configured: bool, workers: usize, vault_path: String, warnings: Vec<String> }
struct Engine {
    root: PathBuf, defs: RwLock<Arc<Definitions>>, vault: Mutex<Vault>, progress: Mutex<Progress>,
    findings: Mutex<HashMap<String, Finding>>, cancel: AtomicBool, paused: AtomicBool, active: AtomicBool,
    watching: AtomicBool, watcher: Mutex<Option<watcher::WatcherHandle>>, workers: usize,
    last_event: Mutex<Instant>, shutdown: AtomicBool,
    updates: Mutex<()>, watcher_incomplete: AtomicU64, last_health: Mutex<Instant>,
}
type Shared = Arc<Engine>;
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> { mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) }
fn definitions(engine: &Engine) -> Arc<Definitions> { engine.defs.read().unwrap_or_else(|p| p.into_inner()).clone() }
fn status(engine: &Engine) -> Status {
    let mut warnings = vec!["Monitoraggio user-mode: non blocca l'esecuzione prima dell'apertura.".into(), "Database iniziale limitato a test di integrazione; non è un feed completo di malware.".into(), "Minifilter, anti-exploit, ONNX e analisi della memoria dei processi non disponibili.".into()];
    #[cfg(not(feature="yara"))] warnings.push("YARA non incluso: ricompilare con feature yara per abilitarlo.".into());
    if let Some(w) = lock(&engine.watcher).as_ref() { let n = w.dropped.load(Ordering::Relaxed); if n > 0 { warnings.push(format!("Watcher: {n} eventi persi o non analizzabili; copertura degradata.")); } }
    let incomplete=engine.watcher_incomplete.load(Ordering::Relaxed); if incomplete>0 {warnings.push(format!("Monitoraggio: {incomplete} analisi incomplete o file non leggibili dall avvio."));}
    Status { version: env!("CARGO_PKG_VERSION"), watcher_enabled: engine.watching.load(Ordering::Acquire), definitions_version: definitions(engine).manifest.version, update_configured: updater::configured(), workers: engine.workers, vault_path: engine.root.join("Quarantine").display().to_string(), warnings }
}
fn progress_event(app: &tauri::AppHandle, engine: &Engine, force: bool) {
    let mut last = lock(&engine.last_event);
    if force || last.elapsed() >= Duration::from_millis(50) { *last = Instant::now(); let _ = app.emit("scan-progress", lock(&engine.progress).clone()); }
}
fn record(app: &tauri::AppHandle, engine: &Engine, path: &std::path::Path, result: scanner::Analysis, watched: bool) {
    if result.anomalies.is_empty() { return; }
    let canonical = match path.canonicalize() { Ok(path) => path, Err(_) => return };
    let mut findings = lock(&engine.findings);
    if findings.values().any(|f| f.path == canonical.display().to_string() && f.sha256 == result.sha256) { return; }
    if findings.len() >= 1000 { let mut p = lock(&engine.progress); p.errors += 1; return; }
    let finding = Finding { id: uuid::Uuid::new_v4().to_string(), name: path.file_name().unwrap_or_default().to_string_lossy().into_owned(), path: canonical.display().to_string(), sha256: result.sha256, md5: result.md5, entropy: result.entropy, anomalies: result.anomalies, coverage: result.coverage, verdict: if result.malicious { "malicious" } else { "suspicious" }.into(), severity: if result.malicious { "Alta" } else { "Media" }.into(), status: "active".into() };
    findings.insert(finding.id.clone(), finding.clone()); drop(findings);
    if watched {
        let _ = app.emit("watcher-alert", &finding);
        let _ = app.notification().builder().title("Aegis Security · rilevamento").body(format!("{}: richiede verifica. Nessuna quarantena automatica.", finding.name)).show();
    } else { let mut p = lock(&engine.progress); p.found += 1; drop(p); let _ = app.emit("scan-finding", &finding); }
}
#[tauri::command] fn get_status(engine: tauri::State<'_, Shared>) -> Status { status(&engine) }
#[tauri::command] fn get_scan_snapshot(engine: tauri::State<'_, Shared>) -> Progress { lock(&engine.progress).clone() }
#[tauri::command] fn get_findings(engine: tauri::State<'_, Shared>) -> Vec<Finding> { lock(&engine.findings).values().cloned().collect() }
#[tauri::command] fn pause_scan(paused: bool, app: tauri::AppHandle, engine: tauri::State<'_, Shared>) -> Result<(), String> {
    { let mut progress = lock(&engine.progress);
      if !engine.active.load(Ordering::Acquire) || !["running","paused"].contains(&progress.status.as_str()) { return Err("Nessuna scansione attiva".into()); }
      engine.paused.store(paused, Ordering::Release); progress.status = if paused { "paused" } else { "running" }.into(); }
    progress_event(&app, &engine, true); Ok(())
}
#[tauri::command] fn cancel_scan(engine: tauri::State<'_, Shared>) { engine.cancel.store(true, Ordering::Release); engine.paused.store(false, Ordering::Release); }
fn begin_scan(mode: String, paths: Vec<String>, app: tauri::AppHandle, engine: Shared) -> Result<String> {
    if engine.active.load(Ordering::Acquire) { return Err(anyhow!("Scansione già attiva")); }
    if !["quick", "full", "custom"].contains(&mode.as_str()) { return Err(anyhow!("Modalità non valida")); }
    let mut roots: Vec<PathBuf> = match mode.as_str() {
        "quick" => scanner::quick_roots(),
        "full" => { #[cfg(windows)] { vec![PathBuf::from(format!("{}\\", std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())))] } #[cfg(not(windows))] { vec![PathBuf::from("/")] } },
        _ => { if paths.is_empty() || paths.len() > 64 { return Err(anyhow!("Scegli da 1 a 64 percorsi")); } paths.into_iter().map(PathBuf::from).collect() }
    };
    roots = roots.into_iter().map(|p| p.canonicalize()).collect::<std::io::Result<Vec<_>>>()?;
    roots.sort(); roots.dedup(); let mut reduced = Vec::new();
    for root in roots { if !reduced.iter().any(|p: &PathBuf| root.starts_with(p)) { reduced.push(root); } }
    if engine.active.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed).is_err() { return Err(anyhow!("Scansione già attiva")); }
    engine.cancel.store(false, Ordering::Release); engine.paused.store(false, Ordering::Release);
    let id = uuid::Uuid::new_v4().to_string();
    *lock(&engine.progress) = Progress { id: id.clone(), kind: mode, status: "running".into(), ..Progress::default() };
    progress_event(&app, &engine, true);
    let failure_state = engine.clone();
    let spawned = std::thread::Builder::new().name("aegis-scan-coordinator".into()).spawn(move || {
        let (tx, rx) = crossbeam_channel::bounded::<PathBuf>(128); let started = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..engine.workers {
                let receiver = rx.clone(); let engine = &engine; let app = &app;
                scope.spawn(move || {
                    for path in receiver {
                        if engine.cancel.load(Ordering::Acquire) { break; }
                        while engine.paused.load(Ordering::Acquire) && !engine.cancel.load(Ordering::Acquire) { std::thread::sleep(Duration::from_millis(50)); }
                        let result = scanner::analyze_file(&path, &definitions(engine), &engine.cancel);
                        { let mut p = lock(&engine.progress); p.files += 1; p.path = path.display().to_string(); p.rate = p.files as f64 / started.elapsed().as_secs_f64().max(0.001); if result.is_err() { p.errors += 1; } if result.as_ref().map(|r| !r.coverage.is_empty()).unwrap_or(false) { p.incomplete += 1; } }
                        if let Ok(result) = result { record(app, engine, &path, result, false); }
                        progress_event(app, engine, false);
                    }
                });
            }
            drop(rx);
            'roots: for root in reduced {
                let iter = walkdir::WalkDir::new(root).follow_links(false).max_open(16).into_iter().filter_entry(|e| !scanner::excluded(e) && !e.path().starts_with(&engine.root));
                for entry in iter {
                    if engine.cancel.load(Ordering::Acquire) { break 'roots; }
                    match entry { Ok(e) if e.file_type().is_file() => { if tx.send(e.into_path()).is_err() { break 'roots; } }, Err(_) => lock(&engine.progress).errors += 1, _ => {} }
                }
            }
            drop(tx);
        });
        { let mut p = lock(&engine.progress); p.status = if engine.cancel.load(Ordering::Acquire) { "cancelled" } else { "done" }.into(); p.rate = 0.0; engine.active.store(false, Ordering::Release); }
        progress_event(&app, &engine, true);
    });
    if let Err(error) = spawned { failure_state.active.store(false, Ordering::Release); lock(&failure_state.progress).status = "cancelled".into(); return Err(error).context("Cannot start scanner"); }
    Ok(id)
}
#[tauri::command] async fn start_scan(mode: String, paths: Vec<String>, app: tauri::AppHandle, engine: tauri::State<'_, Shared>) -> Result<String, String> {
    let engine=engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move||begin_scan(mode,paths,app,engine).map_err(|e|e.to_string())).await.map_err(|e|e.to_string())?
}
fn external_scan(app:tauri::AppHandle,engine:Shared,path:String) {
    tauri::async_runtime::spawn_blocking(move||{if let Err(error)=begin_scan("custom".into(),vec![path],app.clone(),engine){let _=app.emit("scan-error",error.to_string());}});
}
#[tauri::command] async fn list_quarantine(engine: tauri::State<'_, Shared>) -> Result<Vec<VaultEntry>, String> {
    let engine = engine.inner().clone(); tauri::async_runtime::spawn_blocking(move || lock(&engine.vault).list().map_err(|e| e.to_string())).await.map_err(|e| e.to_string())?
}
#[tauri::command] async fn quarantine_file(finding_id: String, engine: tauri::State<'_, Shared>) -> Result<VaultEntry, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let finding = lock(&engine.findings).get(&finding_id).cloned().ok_or("Rilevamento non trovato")?;
        let entry = lock(&engine.vault).isolate(std::path::Path::new(&finding.path), &finding.sha256, &finding.anomalies.join("; ")).map_err(|e| e.to_string())?;
        if entry.status == "held" { lock(&engine.findings).remove(&finding_id); } Ok(entry)
    }).await.map_err(|e| e.to_string())?
}
#[tauri::command] async fn restore_quarantine(id: String, engine: tauri::State<'_, Shared>) -> Result<String, String> {
    let engine = engine.inner().clone(); tauri::async_runtime::spawn_blocking(move || lock(&engine.vault).restore(&id).map_err(|e| e.to_string())).await.map_err(|e| e.to_string())?
}
#[tauri::command] async fn delete_quarantine(id: String, engine: tauri::State<'_, Shared>) -> Result<(), String> {
    let engine = engine.inner().clone(); tauri::async_runtime::spawn_blocking(move || lock(&engine.vault).delete(&id).map_err(|e| e.to_string())).await.map_err(|e| e.to_string())?
}
fn watch(enabled: bool, app: &tauri::AppHandle, engine: &Shared) -> Result<bool> {
    let mut current = lock(&engine.watcher);
    if !enabled { engine.watching.store(false, Ordering::Release); current.take(); return Ok(false); }
    if current.is_some() { return Ok(true); }
    let weak = Arc::downgrade(engine); let handle = app.clone();
    let watcher = watcher::start(watcher::roots(), Arc::new(move |path| {
        let Some(engine) = weak.upgrade() else { return };
        if !engine.watching.load(Ordering::Acquire) || path.starts_with(&engine.root) { return; }
        // One watcher worker, separate from the bounded manual pool. Locked files
        // are retried after later events, never escalated or force-opened.
        let result=scanner::analyze_file(&path, &definitions(&engine), &engine.shutdown);
        if result.as_ref().map(|analysis| !analysis.coverage.is_empty()).unwrap_or(true) {
            engine.watcher_incomplete.fetch_add(1, Ordering::Relaxed);
            let mut last=lock(&engine.last_health);
            if last.elapsed()>=Duration::from_secs(1) { *last=Instant::now(); let _=handle.emit("engine-status",status(&engine)); }
        }
        if let Ok(result)=result {
            if engine.watching.load(Ordering::Acquire) { record(&handle, &engine, &path, result, true); }
        }
    }))?;
    *current = Some(watcher); engine.watching.store(true, Ordering::Release); Ok(true)
}
#[tauri::command] async fn set_watcher(enabled: bool, app: tauri::AppHandle, engine: tauri::State<'_, Shared>) -> Result<bool, String> {
    let result = watch(enabled, &app, engine.inner()).map_err(|e| e.to_string())?; let _ = app.emit("engine-status", status(&engine)); Ok(result)
}
#[derive(Serialize)] struct UpdateResponse { updated: bool, message: String }
#[tauri::command] async fn check_updates(app: tauri::AppHandle, engine: tauri::State<'_, Shared>) -> Result<UpdateResponse, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || -> Result<UpdateResponse, String> {
        let _update = lock(&engine.updates);
        if !updater::configured() { return Ok(UpdateResponse { updated: false, message: "Feed HTTPS e chiave Ed25519 non configurati.".into() }); }
        match updater::check(&engine.root, &definitions(&engine)).map_err(|e| e.to_string())? {
            Some(defs) => { *engine.defs.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(defs); let _ = app.emit("engine-status", status(&engine)); Ok(UpdateResponse { updated: true, message: "Definizioni verificate e attivate.".into() }) },
            None => Ok(UpdateResponse { updated: false, message: "Nessun aggiornamento disponibile.".into() })
        }
    }).await.map_err(|e| e.to_string())?
}
pub fn run() {
    if let Err(error) = crate::platform::require_standard_user() { startup_error(&error.to_string()); return; }
    let root = match crate::platform::private_root() { Ok(p) => p, Err(e) => { startup_error(&format!("Cartella dati: {e:#}")); return; } };
    let defs = match updater::load_cached(&root).and_then(|cached| match cached { Some(d) => Ok(d), None => Definitions::bundled() }) { Ok(d) => d, Err(_) => match Definitions::bundled() { Ok(d) => d, Err(e) => { eprintln!("Definitions: {e}"); return; } } };
    let vault = match Vault::open(&root.join("Quarantine")) { Ok(v) => v, Err(e) => { startup_error(&format!("Quarantena: {e:#}")); return; } };
    let engine = Arc::new(Engine { root, defs: RwLock::new(Arc::new(defs)), vault: Mutex::new(vault), progress: Mutex::new(Progress::default()), findings: Mutex::new(HashMap::new()), cancel: AtomicBool::new(false), paused: AtomicBool::new(false), active: AtomicBool::new(false), watching: AtomicBool::new(false), watcher: Mutex::new(None), workers: std::thread::available_parallelism().map(|n| n.get().saturating_sub(1).clamp(1, 4)).unwrap_or(1), last_event: Mutex::new(Instant::now()), shutdown: AtomicBool::new(false), updates: Mutex::new(()), watcher_incomplete: AtomicU64::new(0), last_health: Mutex::new(Instant::now()) });
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _| { if let Some(window) = app.get_webview_window("main") { let _ = window.show(); let _ = window.set_focus(); } if let Some(index) = args.iter().position(|a| a == "--scan") { if let Some(path) = args.get(index + 1) { let state = app.state::<Shared>().inner().clone(); external_scan(app.clone(),state,path.clone()); } } }))
        .plugin(tauri_plugin_dialog::init()).plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, None))
        .manage(engine.clone())
        .invoke_handler(tauri::generate_handler![get_status, get_scan_snapshot, get_findings, start_scan, pause_scan, cancel_scan, list_quarantine, quarantine_file, restore_quarantine, delete_quarantine, set_watcher, check_updates])
        .setup(|app| {
            use tauri::{menu::{Menu, MenuItem}, tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState}};
            let show = MenuItem::with_id(app, "show", "Apri Aegis Security", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Esci e interrompi il monitoraggio", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let mut tray = TrayIconBuilder::new().menu(&menu).tooltip("Aegis Security · monitoraggio user-mode")
                .on_menu_event(|app, event| match event.id.as_ref() { "show" => { if let Some(w) = app.get_webview_window("main") { let _ = w.show(); let _ = w.set_focus(); } }, "quit" => app.exit(0), _ => {} })
                .on_tray_icon_event(|tray, event| { if matches!(event, TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. }) { if let Some(w) = tray.app_handle().get_webview_window("main") { let _ = w.show(); let _ = w.set_focus(); } } });
            if let Some(icon) = app.default_window_icon() { tray = tray.icon(icon.clone()); } tray.build(app)?;
            let state = app.state::<Shared>().inner().clone(); let _ = watch(true, app.handle(), &state);
            if updater::configured() {
                let weak = Arc::downgrade(&state); let handle = app.handle().clone();
                std::thread::Builder::new().name("aegis-definitions-update".into()).spawn(move || loop {
                    std::thread::park_timeout(Duration::from_secs(6 * 3600));
                    let Some(state) = weak.upgrade() else { break };
                    if state.shutdown.load(Ordering::Acquire) { break; }
                    let _update = lock(&state.updates);
                    if let Ok(Some(updated)) = updater::check(&state.root, &definitions(&state)) {
                        *state.defs.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(updated); let _ = handle.emit("engine-status", status(&state));
                    }
                })?;
            }
            let args: Vec<_> = std::env::args().collect();
            if let Some(index) = args.iter().position(|a| a == "--scan") { if let Some(path) = args.get(index + 1) { external_scan(app.handle().clone(),state,path.clone()); } }
            Ok(())
        })
        .on_window_event(|window, event| { if let tauri::WindowEvent::CloseRequested { api, .. } = event { api.prevent_close(); let _ = window.hide(); } });
    match builder.build(tauri::generate_context!()) {
        Ok(app) => app.run(move |_, event| { if matches!(event, tauri::RunEvent::Exit) { engine.shutdown.store(true, Ordering::Release); engine.cancel.store(true, Ordering::Release); lock(&engine.watcher).take(); } }),
        Err(error) => startup_error(&format!("Avvio applicazione: {error:#}"))
    }
}
fn startup_error(message: &str) {
    eprintln!("{message}");
    #[cfg(windows)] unsafe {
        #[link(name="user32")] extern "system" { fn MessageBoxW(window: *mut std::ffi::c_void, text: *const u16, caption: *const u16, flags: u32) -> i32; }
        let text: Vec<_> = message.encode_utf16().chain(Some(0)).collect();
        let title: Vec<_> = "Aegis Security".encode_utf16().chain(Some(0)).collect();
        MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), 0x10);
    }
}
