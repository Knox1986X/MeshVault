use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::RwLock;

use meshvault_crypto::{
    disable_core_dumps, unwrap_fek, ChunkedBlobReader, LockedSecretBox, MasterVaultKey,
    SecretString, KEY_LEN, WRAPPED_FEK_LEN,
};
use meshvault_import::{
    strip_metadata_for_clean_export, DedupPolicy, ImportOptions, ImportPipeline,
};
use meshvault_storage::{
    atomic_write_file, MediaEntry, VaultCatalog, VaultDoctorReport, VaultLayout,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopMediaItem {
    pub id: Uuid,
    pub original_name: String,
    pub mime_type: String,
    pub plaintext_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamResponse {
    pub status: u16,
    pub mime_type: String,
    pub body: Vec<u8>,
    pub content_range: Option<String>,
}

struct UnlockedDesktopSession {
    layout: VaultLayout,
    locked_mvk: LockedSecretBox<KEY_LEN>,
    catalog: VaultCatalog,
}

/// Thread-safe desktop vault bridge shared between Tauri commands and the `meshvault://` protocol.
pub struct DesktopVaultBridge {
    inner: RwLock<Option<UnlockedDesktopSession>>,
}

impl Default for DesktopVaultBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl DesktopVaultBridge {
    pub fn new() -> Self {
        let _ = disable_core_dumps();
        Self {
            inner: RwLock::new(None),
        }
    }

    /// Ensures Baloo / Tracker / Android indexers never index the vault directory.
    pub fn ensure_indexer_exclusions(vault_dir: &Path) -> Result<(), String> {
        atomic_write_file(&vault_dir.join(".nomedia"), b"")
            .map_err(|e| format!("failed to write .nomedia: {e}"))?;
        atomic_write_file(&vault_dir.join(".noindex"), b"")
            .map_err(|e| format!("failed to write .noindex: {e}"))?;
        Ok(())
    }

    pub fn unlock_vault(&self, vault_dir: &Path, passphrase: &str) -> Result<Uuid, String> {
        let _ = disable_core_dumps();
        Self::ensure_indexer_exclusions(vault_dir)?;

        let layout = VaultLayout::new(vault_dir);
        let header = layout
            .load_header()
            .map_err(|e| format!("failed to load header: {e}"))?;
        let secret = SecretString::from(passphrase.to_string());
        let mvk = header
            .unlock_with_passphrase(&secret)
            .map_err(|e| format!("unlock failed: {e}"))?;
        let catalog = layout
            .load_catalog(&mvk)
            .map_err(|e| format!("failed to open catalog: {e}"))?;
        let locked_mvk = LockedSecretBox::new(*mvk.expose());

        let vault_id = header.vault_id;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| "lock poisoned".to_string())?;
        *guard = Some(UnlockedDesktopSession {
            layout,
            locked_mvk,
            catalog,
        });
        Ok(vault_id)
    }

    pub fn lock_vault(&self) {
        if let Ok(mut guard) = self.inner.write() {
            *guard = None;
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.read().map(|g| g.is_some()).unwrap_or(false)
    }

    pub fn list_media(&self) -> Result<Vec<DesktopMediaItem>, String> {
        let guard = self.inner.read().map_err(|_| "lock poisoned".to_string())?;
        let sess = guard
            .as_ref()
            .ok_or_else(|| "vault is locked".to_string())?;
        Ok(sess
            .catalog
            .timeline_media()
            .into_iter()
            .map(|m| DesktopMediaItem {
                id: m.id,
                original_name: m.original_name.clone(),
                mime_type: m.mime_type.clone(),
                plaintext_size: m.plaintext_size,
            })
            .collect())
    }

    /// Handles Drag-and-Drop of files and recursive directories from CachyOS file managers.
    pub fn import_dropped_paths(
        &self,
        paths: &[PathBuf],
        now_unix_ms: u64,
    ) -> Result<usize, String> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| "lock poisoned".to_string())?;
        let sess = guard
            .as_mut()
            .ok_or_else(|| "vault is locked".to_string())?;
        let mvk = MasterVaultKey::from_bytes(*sess.locked_mvk.expose());
        let root_id = sess.catalog.root_folder_id;
        let mut imported = 0usize;

        for path in paths {
            if path.is_dir() {
                let options = ImportOptions::default();
                let report = ImportPipeline::run_directory_import(
                    &sess.layout,
                    &mvk,
                    &mut sess.catalog,
                    path,
                    root_id,
                    &options,
                    now_unix_ms,
                )
                .map_err(|e| format!("dir import failed: {e}"))?;
                imported += report.imported_files;
            } else if path.is_file() {
                let bytes = fs::read(path).map_err(|e| format!("read failed: {e}"))?;
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("dropped.bin");
                let res = ImportPipeline::import_bytes_item(
                    &sess.layout,
                    &mvk,
                    &mut sess.catalog,
                    root_id,
                    &[],
                    name,
                    &bytes,
                    DedupPolicy::SkipDuplicate,
                    None,
                    now_unix_ms,
                )
                .map_err(|e| format!("file import failed: {e}"))?;
                if !res.deduplicated_skip {
                    imported += 1;
                }
            }
        }
        sess.layout
            .save_catalog(&mvk, &sess.catalog)
            .map_err(|e| format!("save catalog failed: {e}"))?;
        Ok(imported)
    }

    pub fn doctor_report(&self) -> Result<VaultDoctorReport, String> {
        let guard = self.inner.read().map_err(|_| "lock poisoned".to_string())?;
        let sess = guard
            .as_ref()
            .ok_or_else(|| "vault is locked".to_string())?;
        Ok(sess.layout.doctor_report(Some(&sess.catalog)))
    }

    /// Streams decrypted chunks purely in RAM for `meshvault://media/<uuid>` (never writes `/tmp`).
    pub fn stream_media(
        &self,
        media_id: Uuid,
        range_header: Option<&str>,
    ) -> Result<StreamResponse, String> {
        let guard = self.inner.read().map_err(|_| "lock poisoned".to_string())?;
        let sess = guard
            .as_ref()
            .ok_or_else(|| "vault is locked".to_string())?;
        let entry: &MediaEntry = sess
            .catalog
            .media
            .get(&media_id)
            .ok_or_else(|| "media not found".to_string())?;
        let mvk = MasterVaultKey::from_bytes(*sess.locked_mvk.expose());
        let wrapped: [u8; WRAPPED_FEK_LEN] = entry
            .wrapped_fek
            .as_slice()
            .try_into()
            .map_err(|_| "bad wrapped FEK".to_string())?;
        let fek = unwrap_fek(&mvk, media_id, &wrapped).map_err(|e| e.to_string())?;
        let file = fs::File::open(sess.layout.blob_path(media_id)).map_err(|e| e.to_string())?;
        let mut reader = ChunkedBlobReader::open(file).map_err(|e| e.to_string())?;

        let total_size = entry.plaintext_size as usize;
        if let Some(range) = range_header.and_then(|h| parse_byte_range(h, total_size)) {
            let (start, end_inclusive) = range;
            let chunk_size = reader.prelude().chunk_size as usize;
            let first_chunk = start / chunk_size;
            let last_chunk = end_inclusive / chunk_size;
            let mut slice_buf = Vec::with_capacity((end_inclusive - start) + 1);
            for c_idx in first_chunk..=last_chunk {
                let plain_chunk = reader
                    .decrypt_chunk_at(&fek, c_idx as u64)
                    .map_err(|e| e.to_string())?;
                let chunk_start_offset = c_idx * chunk_size;
                let lo = start.saturating_sub(chunk_start_offset);
                let hi = (end_inclusive + 1)
                    .saturating_sub(chunk_start_offset)
                    .min(plain_chunk.len());
                if lo < hi {
                    slice_buf.extend_from_slice(&plain_chunk[lo..hi]);
                }
            }
            return Ok(StreamResponse {
                status: 206,
                mime_type: entry.mime_type.clone(),
                body: slice_buf,
                content_range: Some(format!("bytes {start}-{end_inclusive}/{total_size}")),
            });
        }

        let mut full = Vec::with_capacity(total_size);
        reader
            .decrypt_all_to(&fek, &mut full)
            .map_err(|e| e.to_string())?;
        Ok(StreamResponse {
            status: 200,
            mime_type: entry.mime_type.clone(),
            body: full,
            content_range: None,
        })
    }

    pub fn clean_export_bytes(&self, media_id: Uuid) -> Result<Vec<u8>, String> {
        let resp = self.stream_media(media_id, None)?;
        Ok(strip_metadata_for_clean_export(&resp.mime_type, &resp.body))
    }
}

fn parse_byte_range(header: &str, total_len: usize) -> Option<(usize, usize)> {
    if total_len == 0 {
        return None;
    }
    let spec = header.strip_prefix("bytes=")?;
    let (start_str, end_str) = spec.split_once("-")?;
    let start: usize = start_str.trim().parse().ok()?;
    let end = if end_str.trim().is_empty() {
        total_len - 1
    } else {
        end_str.trim().parse::<usize>().ok()?.min(total_len - 1)
    };
    if start <= end && start < total_len {
        Some((start, end))
    } else {
        None
    }
}

/// Linux Secret Service (KWallet / GNOME Keyring) bridge via `secret-tool`.
pub struct SecretServiceBridge;

impl SecretServiceBridge {
    pub fn is_secret_tool_available() -> bool {
        Command::new("which")
            .arg("secret-tool")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn lookup_vault_token(vault_id: Uuid) -> Option<String> {
        let out = Command::new("secret-tool")
            .args([
                "lookup",
                "application",
                "meshvault",
                "vault_id",
                &vault_id.to_string(),
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8(out.stdout)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshvault_crypto::{Argon2Params, VaultHeader};
    use tempfile::TempDir;

    #[test]
    fn desktop_bridge_unlocks_imports_streams_range_in_ram_and_locks() {
        let tmp = TempDir::new().unwrap();
        let vault_dir = tmp.path().join("vault");
        let drop_file = tmp.path().join("hello.txt");
        let payload = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        fs::write(&drop_file, payload).unwrap();

        let pass = SecretString::from("cachyos-secret".to_string());
        let (header, mvk) = VaultHeader::create_with_passphrase(
            &pass,
            Argon2Params::fast_test(),
            1_700_000_000_000,
            0,
        )
        .unwrap();
        let layout = VaultLayout::new(&vault_dir);
        layout.write_header_pair(&header).unwrap();
        let cat = VaultCatalog::new(header.vault_id, 1_700_000_000_000);
        layout.save_catalog(&mvk, &cat).unwrap();

        let bridge = DesktopVaultBridge::new();
        bridge.unlock_vault(&vault_dir, "cachyos-secret").unwrap();
        assert!(bridge.is_unlocked());
        assert!(vault_dir.join(".nomedia").exists());
        assert!(vault_dir.join(".noindex").exists());

        let count = bridge
            .import_dropped_paths(&[drop_file], 1_700_000_001_000)
            .unwrap();
        assert_eq!(count, 1);

        let items = bridge.list_media().unwrap();
        assert_eq!(items.len(), 1);

        let range_resp = bridge
            .stream_media(items[0].id, Some("bytes=10-15"))
            .unwrap();
        assert_eq!(range_resp.status, 206);
        assert_eq!(range_resp.body, b"ABCDEF");

        bridge.lock_vault();
        assert!(!bridge.is_unlocked());
        assert!(bridge.list_media().is_err());
    }
}
