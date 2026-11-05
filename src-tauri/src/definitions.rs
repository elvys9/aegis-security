use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u64,
    pub expires: String,
    pub hashes: HashMap<String, String>,
    #[serde(default)] pub allow: HashSet<String>,
}
#[derive(Clone)]
pub struct Definitions {
    pub manifest: Manifest,
    #[cfg(feature="yara")] pub rules: std::sync::Arc<yara_x::Rules>,
}
impl Definitions {
    pub fn bundled() -> Result<Self> { Self::from_bytes(include_bytes!("../../signatures/initial.mbdb")) }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 8 * 1024 * 1024 || !bytes.starts_with(b"AEGISDB1") { bail!("Invalid definition container"); }
        let manifest: Manifest = serde_json::from_slice(&bytes[8..]).context("Definition JSON")?;
        if manifest.version == 0 || manifest.hashes.len() > 100_000 || manifest.allow.len() > 100_000 { bail!("Definition limits"); }
        chrono::DateTime::parse_from_rfc3339(&manifest.expires)?;
        for hash in manifest.hashes.keys().chain(manifest.allow.iter()) {
            if hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) { bail!("Invalid SHA-256"); }
        }
        if manifest.hashes.values().any(|v| v.len() > 200) { bail!("Definition label too long"); }
        #[cfg(feature="yara")]
        let rules = std::sync::Arc::new(yara_x::compile(include_str!("../../signatures/baseline.yar")).map_err(|e| anyhow::anyhow!(e.to_string()))?);
        Ok(Self { manifest, #[cfg(feature="yara")] rules })
    }
}
