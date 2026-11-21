use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshvault_crypto::{
    CryptoError, MasterVaultKey, VaultHeader, WRAPPED_FEK_LEN, XNONCE_LEN,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Target packed thumbnail container size: 4 MiB.
pub const THUMB_PACK_TARGET_BYTES: usize = 4 * 1024 * 1024;

/// Magic bytes for an encrypted catalog file (`catalog/tree.mvc`).
pub const CATALOG_MAGIC: [u8; 4] = *b"MVC1";

const CATALOG_AAD_PREFIX: &[u8] = b"MVLT-CATALOG-V1";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("catalog serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid catalog format: {0}")]
    InvalidCatalog(String),

    #[error("folder not found: {0}")]
    FolderNotFound(Uuid),
}

/// Canonical filesystem layout of a MeshVault container directory.
#[derive(Debug, Clone)]
pub struct VaultLayout {
    root: PathBuf,
}

impl VaultLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn primary_header_path(&self) -> PathBuf {
        self.root.join("vault.header")
    }

    pub fn backup_header_path(&self) -> PathBuf {
        self.root.join("vault.header.bak")
    }

    pub fn catalog_path(&self) -> PathBuf {
        self.root.join("catalog").join("tree.mvc")
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    pub fn blob_path(&self, file_id: Uuid) -> PathBuf {
        let hex = file_id.simple().to_string();
        let prefix = &hex[..2];
        self.blobs_dir().join(prefix).join(format!("{hex}.mvb"))
    }

    pub fn thumbs_dir(&self) -> PathBuf {
        self.root.join("thumbs")
    }

    pub fn thumb_pack_path(&self, pack_id: Uuid) -> PathBuf {
        self.thumbs_dir()
            .join(format!("pack_{}.mvt", pack_id.simple()))
    }

    pub fn wal_dir(&self) -> PathBuf {
        self.root.join("wal")
    }

    pub fn import_wal_path(&self) -> PathBuf {
        self.wal_dir().join("import.wal")
    }

    /// Initializes the directory skeleton for a new MeshVault container.
    pub fn ensure_directories(&self) -> Result<(), StorageError> {
        fs::create_dir_all(&self.root)?;
        fs::create_dir_all(self.root.join("catalog"))?;
        fs::create_dir_all(self.blobs_dir())?;
        fs::create_dir_all(self.thumbs_dir())?;
        fs::create_dir_all(self.wal_dir())?;
        Ok(())
    }

    /// Writes `vault.header` and `vault.header.bak` using temp-file + fsync + rename.
    pub fn write_header_pair(&self, header: &VaultHeader) -> Result<(), StorageError> {
        self.ensure_directories()?;
        let bytes = header.to_bytes()?;
        atomic_write_file(&self.primary_header_path(), &bytes)?;
        atomic_write_file(&self.backup_header_path(), &bytes)?;
        Ok(())
    }

    /// Loads the newest valid header from `vault.header` or `vault.header.bak`.
    pub fn load_header(&self) -> Result<VaultHeader, StorageError> {
        let primary = fs::read(self.primary_header_path()).ok();
        let backup = fs::read(self.backup_header_path()).ok();
        let header = VaultHeader::select_latest_valid(primary.as_deref(), backup.as_deref())?;
        Ok(header)
    }
}

/// Supported media categories inside the encrypted catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaKind {
    Photo,
    Video,
    RawPhoto,
    DocumentPdf,
    Animation,
    AudioNote,
    MarkdownNote,
}

/// Encrypted folder node inside the hierarchical vault tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderNode {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub blur_shield: bool,
    pub pinned: bool,
    pub cover_media_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub note_markdown: Option<String>,
    pub created_at_unix_ms: u64,
}

/// Offset locator pointing into a 4 MiB encrypted thumbnail pack (`thumbs/pack_*.mvt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThumbLocator {
    pub pack_id: Uuid,
    pub offset: u32,
    pub len: u32,
}

/// Metadata record for an encrypted media item stored strictly inside the encrypted catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaEntry {
    pub id: Uuid,
    pub folder_id: Uuid,
    pub original_name: String,
    pub mime_type: String,
    pub kind: MediaKind,
    pub plaintext_size: u64,
    pub dedup_blake3: [u8; 32],
    pub phash: Option<u64>,
    pub wrapped_fek: Vec<u8>,
    pub thumb: Option<ThumbLocator>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub trashed_at_unix_ms: Option<u64>,
    pub captured_at_unix_ms: Option<u64>,
    pub imported_at_unix_ms: u64,
}

impl MediaEntry {
    pub fn has_valid_wrapped_fek_len(&self) -> bool {
        self.wrapped_fek.len() == WRAPPED_FEK_LEN
    }
}

/// Hierarchical folder tree and media catalog encrypted as `catalog/tree.mvc`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultCatalog {
    pub vault_id: Uuid,
    pub root_folder_id: Uuid,
    pub catalog_revision: u64,
    pub folders: BTreeMap<Uuid, FolderNode>,
    pub media: BTreeMap<Uuid, MediaEntry>,
}

impl VaultCatalog {
    /// Creates an empty vault catalog with a single encrypted root folder.
    pub fn new(vault_id: Uuid, created_at_unix_ms: u64) -> Self {
        let root_folder_id = Uuid::new_v4();
        let mut folders = BTreeMap::new();
        folders.insert(
            root_folder_id,
            FolderNode {
                id: root_folder_id,
                parent_id: None,
                name: "Root".to_string(),
                blur_shield: false,
                pinned: false,
                cover_media_id: None,
                tags: Vec::new(),
                note_markdown: None,
                created_at_unix_ms,
            },
        );

        Self {
            vault_id,
            root_folder_id,
            catalog_revision: 1,
            folders,
            media: BTreeMap::new(),
        }
    }

    /// Creates a subfolder under `parent_id`, preserving arbitrary nesting depth.
    pub fn create_folder(
        &mut self,
        parent_id: Uuid,
        name: impl Into<String>,
        created_at_unix_ms: u64,
    ) -> Result<Uuid, StorageError> {
        if !self.folders.contains_key(&parent_id) {
            return Err(StorageError::FolderNotFound(parent_id));
        }
        let id = Uuid::new_v4();
        self.folders.insert(
            id,
            FolderNode {
                id,
                parent_id: Some(parent_id),
                name: name.into(),
                blur_shield: false,
                pinned: false,
                cover_media_id: None,
                tags: Vec::new(),
                note_markdown: None,
                created_at_unix_ms,
            },
        );
        self.catalog_revision = self.catalog_revision.saturating_add(1);
        Ok(id)
    }

    /// Serializes and encrypts the entire catalog with the MVK-derived catalog key.
    pub fn seal(&self, mvk: &MasterVaultKey) -> Result<Vec<u8>, StorageError> {
        let catalog_key = mvk.derive_catalog_key();
        let cipher = XChaCha20Poly1305::new_from_slice(catalog_key.expose())
            .map_err(|_| StorageError::InvalidCatalog("invalid catalog key length".to_string()))?;

        let json_plain = Zeroizing::new(serde_json::to_vec(self)?);
        let mut nonce_bytes = [0u8; XNONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = catalog_aad(self.vault_id, self.catalog_revision);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: json_plain.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        let mut out = Vec::with_capacity(4 + 16 + 8 + XNONCE_LEN + ciphertext.len());
        out.extend_from_slice(&CATALOG_MAGIC);
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(&self.catalog_revision.to_le_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Authenticates and decrypts a sealed catalog blob into RAM.
    pub fn open(mvk: &MasterVaultKey, sealed: &[u8]) -> Result<Self, StorageError> {
        let min_len = 4 + 16 + 8 + XNONCE_LEN + 16;
        if sealed.len() < min_len {
            return Err(StorageError::InvalidCatalog(
                "sealed catalog is truncated".to_string(),
            ));
        }
        if sealed[0..4] != CATALOG_MAGIC {
            return Err(StorageError::InvalidCatalog(
                "invalid catalog magic".to_string(),
            ));
        }

        let mut vault_bytes = [0u8; 16];
        vault_bytes.copy_from_slice(&sealed[4..20]);
        let vault_id = Uuid::from_bytes(vault_bytes);
        let revision = u64::from_le_bytes([
            sealed[20], sealed[21], sealed[22], sealed[23], sealed[24], sealed[25], sealed[26],
            sealed[27],
        ]);
        let nonce = XNonce::from_slice(&sealed[28..28 + XNONCE_LEN]);
        let ciphertext = &sealed[28 + XNONCE_LEN..];

        let catalog_key = mvk.derive_catalog_key();
        let cipher = XChaCha20Poly1305::new_from_slice(catalog_key.expose())
            .map_err(|_| StorageError::InvalidCatalog("invalid catalog key length".to_string()))?;

        let aad = catalog_aad(vault_id, revision);
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

        let catalog: Self = serde_json::from_slice(&plain)?;
        Ok(catalog)
    }
}

/// Summary report emitted by background integrity checks (`Vault Scrub`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubReport {
    pub checked_blobs: u64,
    pub checked_chunks: u64,
    pub verified_bytes: u64,
    pub corrupted_blobs: Vec<Uuid>,
    pub missing_blobs: Vec<Uuid>,
}

fn catalog_aad(vault_id: Uuid, revision: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CATALOG_AAD_PREFIX.len() + 16 + 8);
    aad.extend_from_slice(CATALOG_AAD_PREFIX);
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&revision.to_le_bytes());
    aad
}

fn atomic_write_file(target: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    let tmp_name = format!(
        ".{}.tmp.{}",
        target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("meshvault"),
        Uuid::new_v4().simple()
    );
    let tmp_path = target.with_file_name(tmp_name);
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    fs::rename(tmp_path, target)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_catalog_hides_folder_names_on_disk() {
        let vault_id = Uuid::new_v4();
        let mvk = MasterVaultKey::generate();
        let mut catalog = VaultCatalog::new(vault_id, 1_700_000_000_000);
        let secret_folder_name = "Passports_2026_Confidential";
        let folder_id = catalog
            .create_folder(catalog.root_folder_id, secret_folder_name, 1_700_000_000_100)
            .expect("create folder");
        let nested_id = catalog
            .create_folder(folder_id, "Visa_Scans", 1_700_000_000_200)
            .expect("create nested folder");

        let sealed = catalog.seal(&mvk).expect("seal catalog");
        // Verify zero plaintext leakage of folder names in ciphertext.
        assert!(!sealed
            .windows(secret_folder_name.len())
            .any(|w| w == secret_folder_name.as_bytes()));
        assert!(!sealed.windows(10).any(|w| w == b"Visa_Scans"));

        let reopened = VaultCatalog::open(&mvk, &sealed).expect("open catalog");
        assert_eq!(reopened.folders.get(&nested_id).unwrap().name, "Visa_Scans");
        assert_eq!(
            reopened.folders.get(&nested_id).unwrap().parent_id,
            Some(folder_id)
        );
    }
}
