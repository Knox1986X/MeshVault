use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::error::SyncError;

/// Canonical Dropbox App Folder root enforced across all cloud sync operations.
pub const DROPBOX_APP_ROOT: &str = "/MeshVault/";

/// Remote zero-knowledge blob storage abstraction (Dropbox App Folder, Local/USB, or Test Mock).
pub trait RemoteSyncTransport: Send + Sync {
    fn put_object(&self, remote_path: &str, data: &[u8]) -> Result<(), SyncError>;
    fn get_object(&self, remote_path: &str) -> Result<Vec<u8>, SyncError>;
    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, SyncError>;
    fn delete_object(&self, remote_path: &str) -> Result<(), SyncError>;

    /// Uploads a large encrypted blob in resumable chunks starting from `resume_offset`.
    fn upload_chunked_resume(
        &self,
        remote_path: &str,
        full_data: &[u8],
        resume_offset: usize,
        _chunk_size: usize,
    ) -> Result<(), SyncError> {
        let _ = resume_offset;
        self.put_object(remote_path, full_data)
    }
}

/// Validates that any cloud path strictly resides inside `/MeshVault/` without path traversal.
pub fn validate_app_folder_path(path: &str) -> Result<(), SyncError> {
    if !path.starts_with(DROPBOX_APP_ROOT) || path.contains("..") {
        return Err(SyncError::ScopeViolation(path.to_string()));
    }
    Ok(())
}

/// OAuth2 PKCE flow generator for Dropbox App Folder (`/MeshVault/` only, zero client secret).
#[derive(Debug, Clone)]
pub struct PkceAuthFlow {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_verifier: String,
    pub code_challenge: String,
}

impl PkceAuthFlow {
    pub fn start(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let verifier = base64url_nopad(&raw);
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = base64url_nopad(&digest);
        Self {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            code_verifier: verifier,
            code_challenge: challenge,
        }
    }

    pub fn build_authorize_url(&self, state_csrf: &str) -> String {
        format!(
            "https://www.dropbox.com/oauth2/authorize?client_id={}&response_type=code&token_access_type=offline&code_challenge={}&code_challenge_method=S256&redirect_uri={}&state={}",
            self.client_id,
            self.code_challenge,
            self.redirect_uri,
            state_csrf,
        )
    }
}

fn base64url_nopad(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        out.push(char::from(TABLE[((triple >> 18) & 0x3F) as usize]));
        out.push(char::from(TABLE[((triple >> 12) & 0x3F) as usize]));
        if i + 1 < input.len() {
            out.push(char::from(TABLE[((triple >> 6) & 0x3F) as usize]));
        }
        if i + 2 < input.len() {
            out.push(char::from(TABLE[(triple & 0x3F) as usize]));
        }
        i += 3;
    }
    out
}

/// Thread-safe in-memory remote store mimicking Dropbox `/MeshVault/` App Folder semantics.
#[derive(Debug, Default, Clone)]
pub struct InMemoryMockRemote {
    objects: Arc<RwLock<BTreeMap<String, Vec<u8>>>>,
    partial_uploads: Arc<RwLock<BTreeMap<String, Vec<u8>>>>,
}

impl InMemoryMockRemote {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inspects all stored ciphertext bytes on the remote server (for zero-plaintext assertions).
    pub fn snapshot_all_objects(&self) -> BTreeMap<String, Vec<u8>> {
        self.objects.read().map(|g| g.clone()).unwrap_or_default()
    }
}

impl RemoteSyncTransport for InMemoryMockRemote {
    fn put_object(&self, remote_path: &str, data: &[u8]) -> Result<(), SyncError> {
        validate_app_folder_path(remote_path)?;
        let mut guard = self.objects.write().expect("lock poisoned");
        guard.insert(remote_path.to_string(), data.to_vec());
        Ok(())
    }

    fn get_object(&self, remote_path: &str) -> Result<Vec<u8>, SyncError> {
        validate_app_folder_path(remote_path)?;
        let guard = self.objects.read().expect("lock poisoned");
        guard
            .get(remote_path)
            .cloned()
            .ok_or_else(|| SyncError::RemoteNotFound(remote_path.to_string()))
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, SyncError> {
        validate_app_folder_path(prefix)?;
        let guard = self.objects.read().expect("lock poisoned");
        Ok(guard
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn delete_object(&self, remote_path: &str) -> Result<(), SyncError> {
        validate_app_folder_path(remote_path)?;
        let mut guard = self.objects.write().expect("lock poisoned");
        guard.remove(remote_path);
        Ok(())
    }

    fn upload_chunked_resume(
        &self,
        remote_path: &str,
        full_data: &[u8],
        resume_offset: usize,
        chunk_size: usize,
    ) -> Result<(), SyncError> {
        validate_app_folder_path(remote_path)?;
        let step = chunk_size.max(1);
        let mut partials = self.partial_uploads.write().expect("lock poisoned");
        let buf = partials
            .entry(remote_path.to_string())
            .or_insert_with(|| full_data[..resume_offset.min(full_data.len())].to_vec());

        let mut pos = buf.len().min(full_data.len());
        while pos < full_data.len() {
            let end = (pos + step).min(full_data.len());
            buf.extend_from_slice(&full_data[pos..end]);
            pos = end;
        }
        let finished = buf.clone();
        partials.remove(remote_path);
        drop(partials);
        self.put_object(remote_path, &finished)
    }
}

/// Filesystem-backed remote target mapped strictly under `<root>/MeshVault/` (USB/Btrfs/LUKS sync).
#[derive(Debug, Clone)]
pub struct LocalDirectoryRemote {
    base_dir: PathBuf,
}

impl LocalDirectoryRemote {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    fn resolve(&self, remote_path: &str) -> Result<PathBuf, SyncError> {
        validate_app_folder_path(remote_path)?;
        let rel = remote_path.trim_start_matches("/");
        Ok(self.base_dir.join(rel))
    }
}

impl RemoteSyncTransport for LocalDirectoryRemote {
    fn put_object(&self, remote_path: &str, data: &[u8]) -> Result<(), SyncError> {
        let target = self.resolve(remote_path)?;
        meshvault_storage::atomic_write_file(&target, data)?;
        Ok(())
    }

    fn get_object(&self, remote_path: &str) -> Result<Vec<u8>, SyncError> {
        let target = self.resolve(remote_path)?;
        if !target.exists() {
            return Err(SyncError::RemoteNotFound(remote_path.to_string()));
        }
        Ok(fs::read(target)?)
    }

    fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, SyncError> {
        let dir = self.resolve(prefix)?;
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        collect_rel_paths(&self.base_dir, &dir, &mut out)?;
        Ok(out)
    }

    fn delete_object(&self, remote_path: &str) -> Result<(), SyncError> {
        let target = self.resolve(remote_path)?;
        if target.exists() {
            fs::remove_file(target)?;
        }
        Ok(())
    }
}

fn collect_rel_paths(
    base_dir: &PathBuf,
    cur: &PathBuf,
    out: &mut Vec<String>,
) -> Result<(), SyncError> {
    if cur.is_file() {
        if let Ok(rel) = cur.strip_prefix(base_dir) {
            out.push(format!("/{}", rel.to_string_lossy().replace("\\", "/")));
        }
        return Ok(());
    }
    for entry in fs::read_dir(cur)? {
        let entry = entry?;
        collect_rel_paths(base_dir, &entry.path(), out)?;
    }
    Ok(())
}
