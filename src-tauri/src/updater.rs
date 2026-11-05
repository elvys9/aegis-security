use crate::definitions::Definitions;
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::{blocking::Client, redirect::Policy, Url};
use serde::{Deserialize, Serialize};
use std::{fs, io::{Read, Write}, path::Path, time::Duration};

const MAX_PAYLOAD: usize = 8 * 1024 * 1024;
const CACHE_MAGIC: &[u8; 8] = b"AEGISS01";

#[derive(Serialize)]
pub struct UpdateResult {
    pub updated: bool,
    pub message: String,
}

#[derive(Deserialize)]
struct Config {
    endpoint: String,
    public_key_ed25519_hex: String,
}

fn config() -> Result<Config> {
    Ok(serde_json::from_str(include_str!("../../signatures/update-config.json"))?)
}

fn public_key(config: &Config) -> Result<Option<VerifyingKey>> {
    if config.public_key_ed25519_hex.is_empty() { return Ok(None); }
    let bytes = hex::decode(&config.public_key_ed25519_hex).context("Invalid update public key")?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("Update public key must be 32 bytes"))?;
    Ok(Some(VerifyingKey::from_bytes(&bytes)?))
}

fn endpoint_url(endpoint: &str) -> Result<Url> {
    let url = Url::parse(endpoint).context("Invalid update endpoint")?;
    if url.scheme() != "https" || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("Update endpoint must be HTTPS without credentials or fragment");
    }
    Ok(url)
}

fn signature_url(endpoint: &Url) -> Url {
    let mut url = endpoint.clone();
    url.set_path(&format!("{}.sig", endpoint.path()));
    url
}

pub fn configured() -> bool {
    config().and_then(|c| Ok(public_key(&c)?.is_some() && endpoint_url(&c.endpoint).is_ok())).unwrap_or(false)
}

fn read_bounded(reader: impl Read, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum { bail!("Update exceeds size limit"); }
    Ok(bytes)
}

fn verify(payload: &[u8], signature: &[u8], key: &VerifyingKey, minimum_version: u64) -> Result<Definitions> {
    if payload.len() > MAX_PAYLOAD { bail!("Definition payload exceeds size limit"); }
    let signature = Signature::from_slice(signature).context("Invalid update signature length")?;
    key.verify_strict(payload, &signature).context("Update signature verification failed")?;
    // No untrusted definition parsing occurs before strict authentication.
    let definitions = Definitions::from_bytes(payload)?;
    if chrono::DateTime::parse_from_rfc3339(&definitions.manifest.expires)? <= chrono::Utc::now() {
        bail!("Definition update has expired");
    }
    if definitions.manifest.version < minimum_version { bail!("Definition rollback rejected"); }
    Ok(definitions)
}

fn cache_read(root: &Path, key: &VerifyingKey, floor: u64) -> Result<Option<Definitions>> {
    let file = match fs::File::open(root.join("definitions.signed")) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let bytes = read_bounded(file, MAX_PAYLOAD + 72)?;
    if bytes.len() < 72 || &bytes[..8] != CACHE_MAGIC { bail!("Invalid signed definition cache"); }
    Ok(Some(verify(&bytes[72..], &bytes[8..72], key, floor)?))
}

pub fn load_cached(root: &Path) -> Result<Option<Definitions>> {
    let Some(key) = public_key(&config()?)? else { return Ok(None); };
    cache_read(root, &key, Definitions::bundled()?.manifest.version)
}

fn persist_cache(root: &Path, payload: &[u8], signature: &[u8]) -> Result<()> {
    fs::create_dir_all(root)?;
    let mut file = tempfile::NamedTempFile::new_in(root)?;
    file.write_all(CACHE_MAGIC)?;
    file.write_all(signature)?;
    file.write_all(payload)?;
    file.as_file().sync_all()?;
    // Atomic replacement keeps payload and signature coherent, including on Windows.
    file.persist(root.join("definitions.signed")).map_err(|e| e.error)?;
    Ok(())
}

pub fn check(root: &Path, current: &Definitions) -> Result<Option<Definitions>> {
    let config = config()?;
    if config.endpoint.is_empty() { return Ok(None); }
    let Some(key) = public_key(&config)? else { return Ok(None); };
    let endpoint = endpoint_url(&config.endpoint)?;
    let client = Client::builder().redirect(Policy::none()).timeout(Duration::from_secs(20)).build()?;
    let download = |url: Url, maximum: usize| -> Result<Vec<u8>> {
        let response = client.get(url).send()?;
        if !response.status().is_success() { bail!("Update HTTP status {}", response.status()); }
        if response.content_length().is_some_and(|size| size > maximum as u64) { bail!("Update exceeds size limit"); }
        read_bounded(response, maximum)
    };
    let payload = download(endpoint.clone(), MAX_PAYLOAD)?;
    let signature = download(signature_url(&endpoint), 64)?;
    let definitions = verify(&payload, &signature, &key, current.manifest.version)?;
    if definitions.manifest.version == current.manifest.version { return Ok(None); }
    persist_cache(root, &payload, &signature)?;
    Ok(Some(definitions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture(version: u64, expires: &str) -> Vec<u8> {
        let mut bytes = b"AEGISDB1".to_vec();
        bytes.extend(serde_json::to_vec(&serde_json::json!({"version":version,"expires":expires,"hashes":{},"allow":[]})).unwrap());
        bytes
    }
    #[test]
    fn authentic_payload_and_equal_version_are_accepted() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let bytes = fixture(2, "2099-01-01T00:00:00Z");
        let sig = key.sign(&bytes).to_bytes();
        assert_eq!(verify(&bytes, &sig, &key.verifying_key(), 2).unwrap().manifest.version, 2);
    }
    #[test]
    fn tamper_wrong_key_and_truncated_signature_are_rejected() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let mut bytes = fixture(2, "2099-01-01T00:00:00Z");
        let sig = key.sign(&bytes).to_bytes();
        assert!(verify(&bytes, &sig[..63], &key.verifying_key(), 1).is_err());
        assert!(verify(&bytes, &sig, &SigningKey::from_bytes(&[18;32]).verifying_key(), 1).is_err());
        bytes[0] ^= 1;
        assert!(verify(&bytes, &sig, &key.verifying_key(), 1).is_err());
    }
    #[test]
    fn rollback_and_expired_definitions_are_rejected() {
        let key = SigningKey::from_bytes(&[17; 32]);
        for (bytes, floor) in [(fixture(2, "2099-01-01T00:00:00Z"),3), (fixture(4, "2000-01-01T00:00:00Z"),1)] {
            assert!(verify(&bytes, &key.sign(&bytes).to_bytes(), &key.verifying_key(), floor).is_err());
        }
    }
    #[test]
    fn bounded_reads_reject_oversize_without_truncation() {
        assert_eq!(read_bounded(&b"1234"[..], 4).unwrap(), b"1234");
        assert!(read_bounded(&b"12345"[..], 4).is_err());
        let key = SigningKey::from_bytes(&[17; 32]);
        assert!(verify(&vec![0; MAX_PAYLOAD + 1], &[0;64], &key.verifying_key(), 0).is_err());
    }
    #[test]
    fn endpoint_policy_and_signature_url() {
        for url in ["http://example.com/db", "https://user:pass@example.com/db", "https://example.com/db#fragment"] {
            assert!(endpoint_url(url).is_err());
        }
        let url = endpoint_url("https://example.com/db?channel=stable").unwrap();
        assert_eq!(signature_url(&url).as_str(), "https://example.com/db.sig?channel=stable");
    }
    #[test]
    fn cache_round_trip_replacement_and_tamper_detection() {
        let root = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[17; 32]);
        assert!(cache_read(root.path(), &key.verifying_key(), 1).unwrap().is_none());
        for version in [2, 3] {
            let bytes = fixture(version, "2099-01-01T00:00:00Z");
            persist_cache(root.path(), &bytes, &key.sign(&bytes).to_bytes()).unwrap();
            assert_eq!(cache_read(root.path(), &key.verifying_key(), 1).unwrap().unwrap().manifest.version, version);
        }
        assert!(cache_read(root.path(), &key.verifying_key(), 4).is_err());
        let path = root.path().join("definitions.signed");
        let mut bytes = fs::read(&path).unwrap();
        bytes[8] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(cache_read(root.path(), &key.verifying_key(), 1).is_err());
    }
}
