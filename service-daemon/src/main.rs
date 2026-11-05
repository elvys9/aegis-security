#[cfg(windows)]
mod windows {
    use std::{ffi::OsString, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};
    use windows_service::{define_windows_service, service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType}, service_control_handler::{self, ServiceControlHandlerResult}, service_dispatcher};
    const NAME: &str = "AegisSecurity";
    define_windows_service!(ffi_service_main, service_main);
    pub fn dispatch() -> windows_service::Result<()> { service_dispatcher::start(NAME, ffi_service_main) }
    fn status(state: ServiceState, code: u32) -> ServiceStatus {
        ServiceStatus { service_type: ServiceType::OWN_PROCESS, current_state: state, controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() }, exit_code: ServiceExitCode::Win32(code), checkpoint: 0, wait_hint: Duration::default(), process_id: None }
    }
    fn service_main(_: Vec<OsString>) {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let handle = match service_control_handler::register(NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => { flag.store(true, Ordering::SeqCst); ServiceControlHandlerResult::NoError },
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) { Ok(handle) => handle, Err(_) => return };
        let _ = handle.set_service_status(status(ServiceState::Running, 0));
        let worker_cancel = cancel.clone();
        let worker = std::thread::spawn(move || aegis_service::runtime::run(worker_cancel));
        let mut checkpoint = 0;
        while !worker.is_finished() {
            if cancel.load(Ordering::SeqCst) {
                checkpoint += 1;
                let mut stopping = status(ServiceState::StopPending, 0);
                stopping.checkpoint = checkpoint;
                stopping.wait_hint = Duration::from_secs(10);
                let _ = handle.set_service_status(stopping);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let success = matches!(worker.join(), Ok(Ok(())));
        // SCM exposes a nonzero exit status if validation or startup fails.
        let _ = handle.set_service_status(status(ServiceState::Stopped, if success { 0 } else { 1 }));
    }
}
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> { windows::dispatch()?; Ok(()) }
#[cfg(not(windows))]
fn main() { eprintln!("AegisSecurity service requires Windows SCM"); std::process::exit(1); }
