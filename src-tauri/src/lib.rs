pub mod definitions;
pub mod scanner;
pub mod quarantine;
pub mod platform;
pub mod watcher;
pub mod updater;
#[cfg(feature = "desktop")]
mod app;
#[cfg(feature = "desktop")]
pub use app::run;
