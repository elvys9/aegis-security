use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub roots: Vec<PathBuf>,
    pub interval_seconds: u64,
    pub workers: usize,
    #[serde(default)]
    pub watch: bool,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if !(60..=604800).contains(&self.interval_seconds) || !(1..=4).contains(&self.workers) || self.roots.is_empty() || self.roots.len() > 32 {
            bail!("Require 1-32 local roots, 1-4 workers and interval 60-604800 seconds");
        }
        for root in &self.roots {
            let value = root.to_string_lossy();
            let bytes = value.as_bytes();
            if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' || value[2..].contains(':') || value.split(['\\','/']).any(|part| part == ".." || part == ".") {
                bail!("Root must be an absolute local drive path without parent components");
            }
        }
        Ok(())
    }
}
