use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use meshvault_crypto::{
    unwrap_fek, Argon2Params, ChunkedBlobReader, MasterVaultKey, RecoveryKit, SecretString,
    VaultHeader, Zeroize, WRAPPED_FEK_LEN,
};
use meshvault_import::{DedupPolicy, ImportOptions, ImportPipeline};
use meshvault_storage::{MediaKind, VaultCatalog, VaultLayout};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

uniffi::setup_scaffolding!();

/// States of the vault security lifecycle state machine.
/// Transitioning back to `Locked` immediately zeroizes MVK and decoded UI buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum VaultSecurityState {
    Locked,
    UnlockingBiometric,
    UnlockingPassphrase,
    UnlockedFull,
    UnlockedSafePresentation,
    UnlockedDecoy,
    LockingZeroize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDedupPolicy {
    SkipDuplicate,
    LinkIntoTargetFolder,
    KeepIndependentCopy,
}

impl From<FfiDedupPolicy> for DedupPolicy {
    fn from(value: FfiDedupPolicy) -> Self {
        match value {
            FfiDedupPolicy::SkipDuplicate => Self::SkipDuplicate,
            FfiDedupPolicy::LinkIntoTargetFolder => Self::LinkIntoTargetFolder,
            FfiDedupPolicy::KeepIndependentCopy => Self::KeepIndependentCopy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiMediaKind {
    Photo,
    Video,
    RawPhoto,
    DocumentPdf,
    Animation,
    AudioNote,
    MarkdownNote,
}

impl From<MediaKind> for FfiMediaKind {
    fn from(value: MediaKind) -> Self {
        match value {
            MediaKind::Photo => Self::Photo,
            MediaKind::Video => Self::Video,
            MediaKind::RawPhoto => Self::RawPhoto,
            MediaKind::DocumentPdf => Self::DocumentPdf,
            MediaKind::Animation => Self::Animation,
            MediaKind::AudioNote => Self::AudioNote,
            MediaKind::MarkdownNote => Self::MarkdownNote,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiFolderDto {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub blur_shield: bool,
    pub pinned: bool,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMediaDto {
    pub id: String,
    pub folder_id: String,
    pub original_name: String,
    pub mime_type: String,
    pub kind: FfiMediaKind,
    pub plaintext_size: u64,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub exif_camera: Option<String>,
    pub micro_thumb_bytes: Option<Vec<u8>>,
    pub favorite: bool,
    pub captured_at_unix_ms: Option<u64>,
    pub imported_at_unix_ms: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiFolderContentsDto {
    pub folder_id: String,
    pub subfolders: Vec<FfiFolderDto>,
    pub media: Vec<FfiMediaDto>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiImportReportDto {
    pub imported_files: u64,
    pub skipped_duplicates: u64,
    pub linked_duplicates: u64,
    pub created_folders: u64,
    pub quarantined_count: u64,
    pub bytes_encrypted: u64,
    pub resumed_from_wal: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiScrubReportDto {
    pub checked_blobs: u64,
    pub checked_chunks: u64,
    pub verified_bytes: u64,
    pub corrupted_count: u64,
    pub missing_count: u64,
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiVaultError {
    #[error("vault is locked")]
    VaultLocked,

    #[error("invalid identifier: {0}")]
    InvalidUuid(String),

    #[error("media entry not found: {0}")]
    MediaNotFound(String),

    #[error("cryptographic failure: {0}")]
    Crypto(#[from] meshvault_crypto::CryptoError),

    #[error("storage failure: {0}")]
    Storage(#[from] meshvault_storage::StorageError),

    #[error("import failure: {0}")]
    Import(#[from] meshvault_import::ImportError),

    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
}

struct SessionInner {
    state: VaultSecurityState,
    layout: VaultLayout,
    header: VaultHeader,
    mvk: Option<MasterVaultKey>,
    catalog: Option<VaultCatalog>,
}

/// Thread-safe UniFFI vault session bridging Rust core with Android Kotlin and CachyOS.
#[derive(uniffi::Object)]
pub struct MeshVaultSession {
    inner: RwLock<SessionInner>,
}

#[uniffi::export]
impl MeshVaultSession {
    /// Creates a brand-new encrypted vault at `vault_dir` and unlocks it in RAM.
    #[uniffi::constructor]
    pub fn create_new(
        vault_dir: String,
        passphrase: String,
        now_unix_ms: u64,
        use_fast_kdf: bool,
    ) -> Result<Arc<Self>, FfiVaultError> {
        let params = if use_fast_kdf {
            Argon2Params::fast_test()
        } else {
            Argon2Params::production_default()
        };
        let secret_pass = SecretString::from(passphrase);
        let (header, mvk) =
            VaultHeader::create_with_passphrase(&secret_pass, params, now_unix_ms, 0)?;
        let layout = VaultLayout::new(PathBuf::from(vault_dir));
        layout.write_header_pair(&header)?;

        let catalog = VaultCatalog::new(header.vault_id, now_unix_ms);
        layout.save_catalog(&mvk, &catalog)?;

        Ok(Arc::new(Self {
            inner: RwLock::new(SessionInner {
                state: VaultSecurityState::UnlockedFull,
                layout,
                header,
                mvk: Some(mvk),
                catalog: Some(catalog),
            }),
        }))
    }

    /// Unlocks an existing vault using a master passphrase.
    #[uniffi::constructor]
    pub fn unlock_with_passphrase(
        vault_dir: String,
        passphrase: String,
    ) -> Result<Arc<Self>, FfiVaultError> {
        let layout = VaultLayout::new(PathBuf::from(vault_dir));
        let header = layout.load_header()?;
        let secret_pass = SecretString::from(passphrase);
        let mvk = header.unlock_with_passphrase(&secret_pass)?;
        let catalog = layout.load_catalog(&mvk)?;

        Ok(Arc::new(Self {
            inner: RwLock::new(SessionInner {
                state: VaultSecurityState::UnlockedFull,
                layout,
                header,
                mvk: Some(mvk),
                catalog: Some(catalog),
            }),
        }))
    }

    /// Unlocks an existing vault using the 24-word Emergency Recovery Kit.
    #[uniffi::constructor]
    pub fn unlock_with_recovery_kit(
        vault_dir: String,
        mnemonic: String,
    ) -> Result<Arc<Self>, FfiVaultError> {
        let layout = VaultLayout::new(PathBuf::from(vault_dir));
        let header = layout.load_header()?;
        let kit = RecoveryKit::from_mnemonic(&mnemonic)?;
        let mvk = header.unlock_with_recovery_kit(&kit)?;
        let catalog = layout.load_catalog(&mvk)?;

        Ok(Arc::new(Self {
            inner: RwLock::new(SessionInner {
                state: VaultSecurityState::UnlockedFull,
                layout,
                header,
                mvk: Some(mvk),
                catalog: Some(catalog),
            }),
        }))
    }

    /// Immediately transitions to LockingZeroize -> Locked and scrubs MVK and catalog from RAM.
    pub fn lock(&self) {
        if let Ok(mut guard) = self.inner.write() {
            guard.state = VaultSecurityState::LockingZeroize;
            if let Some(mut mvk) = guard.mvk.take() {
                mvk.zeroize();
            }
            guard.catalog = None;
            guard.state = VaultSecurityState::Locked;
        }
    }

    /// Returns the current state in the VaultSecurityState machine.
    pub fn security_state(&self) -> VaultSecurityState {
        self.inner
            .read()
            .map(|g| g.state)
            .unwrap_or(VaultSecurityState::Locked)
    }

    /// Returns the UUID string of the root folder inside the encrypted catalog.
    pub fn root_folder_id(&self) -> Result<String, FfiVaultError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        Ok(catalog.root_folder_id.to_string())
    }

    /// Generates and registers a new 24-word Recovery Kit slot in the dual vault header.
    pub fn add_recovery_kit_slot(&self) -> Result<String, FfiVaultError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| FfiVaultError::VaultLocked)?;
        let mvk = guard.mvk.take().ok_or(FfiVaultError::VaultLocked)?;
        let kit = RecoveryKit::generate();
        let res = guard.header.add_recovery_slot(&mvk, &kit);
        guard.mvk = Some(mvk);
        res?;
        guard.layout.write_header_pair(&guard.header)?;
        Ok(kit.to_mnemonic().to_string())
    }

    /// Rotates the master passphrase in milliseconds without touching media blobs.
    pub fn rotate_passphrase(
        &self,
        old_passphrase: String,
        new_passphrase: String,
    ) -> Result<(), FfiVaultError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| FfiVaultError::VaultLocked)?;
        if guard.mvk.is_none() {
            return Err(FfiVaultError::VaultLocked);
        }
        let old_secret = SecretString::from(old_passphrase);
        let new_secret = SecretString::from(new_passphrase);
        guard
            .header
            .rotate_passphrase(&old_secret, &new_secret, None)?;
        guard.layout.write_header_pair(&guard.header)?;
        Ok(())
    }

    /// Creates a new encrypted subfolder under `parent_folder_id`.
    pub fn create_folder(
        &self,
        parent_folder_id: String,
        name: String,
        now_unix_ms: u64,
    ) -> Result<String, FfiVaultError> {
        let parent_uuid = parse_uuid(&parent_folder_id)?;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;

        let id = catalog.create_folder(parent_uuid, name, now_unix_ms)?;
        inner.layout.save_catalog(mvk, catalog)?;
        Ok(id.to_string())
    }

    /// Lists decrypted subfolder and media metadata for `folder_id` in RAM.
    pub fn list_folder_contents(
        &self,
        folder_id: String,
    ) -> Result<FfiFolderContentsDto, FfiVaultError> {
        let target_uuid = parse_uuid(&folder_id)?;
        let guard = self
            .inner
            .read()
            .map_err(|_| FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let (subfolders, items) = catalog.list_folder_contents(target_uuid);

        Ok(FfiFolderContentsDto {
            folder_id,
            subfolders: subfolders
                .into_iter()
                .map(|f| FfiFolderDto {
                    id: f.id.to_string(),
                    parent_id: f.parent_id.map(|p| p.to_string()),
                    name: f.name.clone(),
                    blur_shield: f.blur_shield,
                    pinned: f.pinned,
                    created_at_unix_ms: f.created_at_unix_ms,
                })
                .collect(),
            media: items
                .into_iter()
                .map(|m| FfiMediaDto {
                    id: m.id.to_string(),
                    folder_id: m.folder_id.to_string(),
                    original_name: m.original_name.clone(),
                    mime_type: m.mime_type.clone(),
                    kind: m.kind.into(),
                    plaintext_size: m.plaintext_size,
                    width: m.width,
                    height: m.height,
                    exif_camera: m.exif_camera.clone(),
                    micro_thumb_bytes: m.micro_thumb.clone(),
                    favorite: m.favorite,
                    captured_at_unix_ms: m.captured_at_unix_ms,
                    imported_at_unix_ms: m.imported_at_unix_ms,
                })
                .collect(),
        })
    }

    /// Recursively imports a directory tree with subfolder preservation into the encrypted vault.
    pub fn import_directory(
        &self,
        source_dir: String,
        target_parent_id: String,
        dedup_policy: FfiDedupPolicy,
        now_unix_ms: u64,
    ) -> Result<FfiImportReportDto, FfiVaultError> {
        let parent_uuid = parse_uuid(&target_parent_id)?;
        let mut guard = self
            .inner
            .write()
            .map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;

        let options = ImportOptions {
            dedup_policy: dedup_policy.into(),
            ..ImportOptions::default()
        };
        let report = ImportPipeline::run_directory_import(
            &inner.layout,
            mvk,
            catalog,
            &PathBuf::from(source_dir),
            parent_uuid,
            &options,
            now_unix_ms,
        )?;

        Ok(FfiImportReportDto {
            imported_files: report.imported_files as u64,
            skipped_duplicates: report.skipped_duplicates as u64,
            linked_duplicates: report.linked_duplicates as u64,
            created_folders: report.created_folders as u64,
            quarantined_count: report.quarantined_files.len() as u64,
            bytes_encrypted: report.bytes_encrypted,
            resumed_from_wal: report.resumed_from_wal,
        })
    }

    /// Decrypts a single 1 MiB chunk in O(1) directly into RAM (for Media3 streaming).
    pub fn read_media_chunk(
        &self,
        media_id: String,
        chunk_index: u64,
    ) -> Result<Vec<u8>, FfiVaultError> {
        let uuid = parse_uuid(&media_id)?;
        let guard = self
            .inner
            .read()
            .map_err(|_| FfiVaultError::VaultLocked)?;
        let mvk = guard.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;

        let entry = catalog
            .media
            .get(&uuid)
            .ok_or_else(|| FfiVaultError::MediaNotFound(media_id.clone()))?;
        let wrapped: [u8; WRAPPED_FEK_LEN] = entry
            .wrapped_fek
            .as_slice()
            .try_into()
            .map_err(|_| meshvault_crypto::CryptoError::AuthenticationFailed)?;
        let fek = unwrap_fek(mvk, uuid, &wrapped)?;

        let blob_file = fs::File::open(guard.layout.blob_path(uuid))?;
        let mut reader = ChunkedBlobReader::open(blob_file)?;
        let plain = reader.decrypt_chunk_at(&fek, chunk_index)?;
        Ok(plain.to_vec())
    }

    /// Decrypts all chunks of a media item into an in-memory buffer (for image viewer).
    pub fn read_media_all_bytes(&self, media_id: String) -> Result<Vec<u8>, FfiVaultError> {
        let uuid = parse_uuid(&media_id)?;
        let guard = self
            .inner
            .read()
            .map_err(|_| FfiVaultError::VaultLocked)?;
        let mvk = guard.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;

        let entry = catalog
            .media
            .get(&uuid)
            .ok_or_else(|| FfiVaultError::MediaNotFound(media_id.clone()))?;
        let wrapped: [u8; WRAPPED_FEK_LEN] = entry
            .wrapped_fek
            .as_slice()
            .try_into()
            .map_err(|_| meshvault_crypto::CryptoError::AuthenticationFailed)?;
        let fek = unwrap_fek(mvk, uuid, &wrapped)?;

        let blob_file = fs::File::open(guard.layout.blob_path(uuid))?;
        let mut reader = ChunkedBlobReader::open(blob_file)?;
        let mut out = Vec::with_capacity(entry.plaintext_size as usize);
        reader.decrypt_all_to(&fek, &mut out)?;
        Ok(out)
    }

    /// Decrypts a high-resolution thumbnail from its 4 MiB `.mvt` pack into RAM.
    pub fn read_thumbnail_bytes(&self, media_id: String) -> Result<Vec<u8>, FfiVaultError> {
        let uuid = parse_uuid(&media_id)?;
        let guard = self
            .inner
            .read()
            .map_err(|_| FfiVaultError::VaultLocked)?;
        let mvk = guard.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;

        let entry = catalog
            .media
            .get(&uuid)
            .ok_or_else(|| FfiVaultError::MediaNotFound(media_id.clone()))?;
        let Some(locator) = entry.thumb else {
            return Ok(Vec::new());
        };
        let plain = guard.layout.read_thumbnail(mvk, catalog, uuid, locator)?;
        Ok(plain.to_vec())
    }

    /// Runs Vault Scrub across all encrypted media blobs and returns a health report.
    pub fn scrub_vault(&self) -> Result<FfiScrubReportDto, FfiVaultError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| FfiVaultError::VaultLocked)?;
        let mvk = guard.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;

        let report = guard.layout.scrub_vault(mvk, catalog)?;
        Ok(FfiScrubReportDto {
            checked_blobs: report.checked_blobs,
            checked_chunks: report.checked_chunks,
            verified_bytes: report.verified_bytes,
            corrupted_count: report.corrupted_blobs.len() as u64,
            missing_count: report.missing_blobs.len() as u64,
        })
    }
}

fn parse_uuid(s: &str) -> Result<Uuid, FfiVaultError> {
    Uuid::parse_str(s).map_err(|_| FfiVaultError::InvalidUuid(s.to_string()))
}
