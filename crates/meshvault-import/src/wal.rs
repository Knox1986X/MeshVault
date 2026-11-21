use std::fs;
use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshvault_crypto::{CryptoError, MasterVaultKey, XNONCE_LEN};
use meshvault_storage::atomic_write_file;
use meshvault_storage::VaultLayout;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::{DedupPolicy, ImportState};

const WAL_MAGIC: [u8; 4] = *b"MVW1";
const WAL_AAD_PREFIX: &[u8] = b"MVLT-IMPORT-WAL-V1";

/// Persistent encrypted Write-Ahead Log entry for one source item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalItem {
    pub item_id: Uuid,
    pub relative_folder_segments: Vec<String>,
    pub file_name: String,
    pub source_path: PathBuf,
    pub state: ImportState,
    pub verified_chunks: u64,
    pub total_chunks: u64,
    pub quarantine_reason: Option<String>,
}

/// Encrypted transactional import journal stored at `wal/import.wal`.
/// Zero source paths or filenames are stored in plaintext on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportWal {
    pub job_id: Uuid,
    pub target_parent_id: Uuid,
    pub dedup_policy: DedupPolicy,
    pub chunk_size: usize,
    pub generate_thumbnails: bool,
    pub created_at_unix_ms: u64,
    pub items: Vec<WalItem>,
}

impl ImportWal {
    /// Seals and atomically persists the import WAL to `wal/import.wal`.
    pub fn save(&self, layout: &VaultLayout, mvk: &MasterVaultKey) -> Result<(), ImportError> {
        layout.ensure_directories()?;
        let key = mvk.derive_catalog_key();
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| ImportError::WalFormat("invalid WAL key length".to_string()))?;

        let plain = Zeroizing::new(
            serde_json::to_vec(self).map_err(|e| ImportError::WalFormat(e.to_string()))?,
        );
        let mut nonce_bytes = [0u8; XNONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = wal_aad(self.job_id);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plain.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        let mut out = Vec::with_capacity(4 + 16 + XNONCE_LEN + ciphertext.len());
        out.extend_from_slice(&WAL_MAGIC);
        out.extend_from_slice(self.job_id.as_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);

        atomic_write_file(&layout.import_wal_path(), &out)?;
        Ok(())
    }

    /// Loads and authenticates an existing `wal/import.wal` if present.
    pub fn load(layout: &VaultLayout, mvk: &MasterVaultKey) -> Result<Option<Self>, ImportError> {
        let wal_path = layout.import_wal_path();
        if !wal_path.exists() {
            return Ok(None);
        }

        let raw = fs::read(&wal_path)?;
        let min_len = 4 + 16 + XNONCE_LEN + 16;
        if raw.len() < min_len || raw[0..4] != WAL_MAGIC {
            return Err(ImportError::WalFormat("invalid or truncated WAL".to_string()));
        }

        let mut job_bytes = [0u8; 16];
        job_bytes.copy_from_slice(&raw[4..20]);
        let job_id = Uuid::from_bytes(job_bytes);
        let nonce = XNonce::from_slice(&raw[20..20 + XNONCE_LEN]);
        let ciphertext = &raw[20 + XNONCE_LEN..];

        let key = mvk.derive_catalog_key();
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| ImportError::WalFormat("invalid WAL key length".to_string()))?;
        let aad = wal_aad(job_id);

        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        );

        let wal: Self =
            serde_json::from_slice(&plain).map_err(|e| ImportError::WalFormat(e.to_string()))?;
        Ok(Some(wal))
    }

    /// Removes `wal/import.wal` after all transactions reach a terminal state.
    pub fn clear(layout: &VaultLayout) -> Result<(), ImportError> {
        let wal_path = layout.import_wal_path();
        if wal_path.exists() {
            fs::remove_file(wal_path)?;
        }
        Ok(())
    }
}

fn wal_aad(job_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WAL_AAD_PREFIX.len() + 16);
    aad.extend_from_slice(WAL_AAD_PREFIX);
    aad.extend_from_slice(job_id.as_bytes());
    aad
}
