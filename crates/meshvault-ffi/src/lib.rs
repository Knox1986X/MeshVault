use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use meshvault_crypto::{
    unwrap_fek, Argon2Params, ChunkedBlobReader, KeyWrappingKey, MasterVaultKey, RecoveryKit,
    SecretString, VaultHeader, Zeroize, KEY_LEN, WRAPPED_FEK_LEN,
};
use meshvault_import::{
    strip_metadata_for_clean_export, DedupPolicy, ImportOptions, ImportPipeline,
};
use meshvault_storage::{AuditEventKind, AuditLogEntry, MediaKind, VaultCatalog, VaultLayout};
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
    pub subfolder_count: u64,
    pub media_count: u64,
    pub total_bytes: u64,
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
    pub tags: Vec<String>,
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
pub struct FfiSingleImportResultDto {
    pub media_id: String,
    pub target_folder_id: String,
    pub deduplicated_skip: bool,
    pub deduplicated_link: bool,
    pub bytes_encrypted: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiVaultMetricsDto {
    pub vault_id: String,
    pub header_revision: u64,
    pub folder_count: u64,
    pub total_media: u64,
    pub total_bytes: u64,
    pub photo_count: u64,
    pub photo_bytes: u64,
    pub video_count: u64,
    pub video_bytes: u64,
    pub raw_count: u64,
    pub raw_bytes: u64,
    pub doc_count: u64,
    pub doc_bytes: u64,
    pub audio_count: u64,
    pub audio_bytes: u64,
    pub thumb_pack_bytes: u64,
    pub trashed_count: u64,
    pub trashed_bytes: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiScrubReportDto {
    pub checked_blobs: u64,
    pub checked_chunks: u64,
    pub verified_bytes: u64,
    pub corrupted_count: u64,
    pub missing_count: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSimilarGroupDto {
    pub anchor_dhash_hex: String,
    pub media_ids: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAuditEventDto {
    pub timestamp_unix_ms: u64,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiDoctorReportDto {
    pub primary_header_valid: bool,
    pub backup_header_valid: bool,
    pub header_revision: u64,
    pub key_slot_count: u32,
    pub decoy_configured: bool,
    pub media_count: u64,
    pub trashed_count: u64,
    pub missing_blobs_count: u64,
    pub thumb_pack_count: u64,
    pub wal_pending: bool,
}

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiVaultError {
    #[error("vault is locked")]
    VaultLocked,

    #[error("invalid identifier: {0}")]
    InvalidUuid(String),

    #[error("invalid wrapping key length (expected 32 bytes)")]
    InvalidWrappingKeyLength,

    #[error("folder not found: {0}")]
    FolderNotFound(String),

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

    /// Unlocks an existing vault using a master passphrase (or decoy passphrase if configured).
    #[uniffi::constructor]
    pub fn unlock_with_passphrase(
        vault_dir: String,
        passphrase: String,
    ) -> Result<Arc<Self>, FfiVaultError> {
        let layout = VaultLayout::new(PathBuf::from(vault_dir));
        let header = layout.load_header()?;
        let secret_pass = SecretString::from(passphrase);

        if let Ok(mvk) = header.unlock_with_passphrase(&secret_pass) {
            let catalog = layout.load_catalog(&mvk)?;
            let _ = layout.reset_failed_unlocks();
            let _ = layout.append_audit_event(
                &mvk,
                header.vault_id,
                AuditLogEntry {
                    timestamp_unix_ms: header.created_at_unix_ms,
                    kind: AuditEventKind::UnlockSuccess,
                    detail: "Unlocked full vault with passphrase".to_string(),
                },
            );
            return Ok(Arc::new(Self {
                inner: RwLock::new(SessionInner {
                    state: VaultSecurityState::UnlockedFull,
                    layout,
                    header,
                    mvk: Some(mvk),
                    catalog: Some(catalog),
                }),
            }));
        }

        if let Ok(decoy_mvk) = header.unlock_with_decoy_passphrase(&secret_pass) {
            let decoy_catalog = layout.load_decoy_catalog(&decoy_mvk)?;
            let _ = layout.reset_failed_unlocks();
            return Ok(Arc::new(Self {
                inner: RwLock::new(SessionInner {
                    state: VaultSecurityState::UnlockedDecoy,
                    layout,
                    header,
                    mvk: Some(decoy_mvk),
                    catalog: Some(decoy_catalog),
                }),
            }));
        }

        let _ = layout.record_failed_unlock(header.created_at_unix_ms);
        Err(FfiVaultError::Crypto(
            meshvault_crypto::CryptoError::SlotNotFound,
        ))
    }

    /// Unlocks an existing vault using a 32-byte key protected by Android Keystore / BiometricPrompt.
    #[uniffi::constructor]
    pub fn unlock_with_hardware_key(
        vault_dir: String,
        slot_id: String,
        wrapping_key_bytes: Vec<u8>,
    ) -> Result<Arc<Self>, FfiVaultError> {
        let slot_uuid = parse_uuid(&slot_id)?;
        let raw_kek: [u8; KEY_LEN] = wrapping_key_bytes
            .try_into()
            .map_err(|_| FfiVaultError::InvalidWrappingKeyLength)?;
        let kek = KeyWrappingKey::from_bytes(raw_kek);

        let layout = VaultLayout::new(PathBuf::from(vault_dir));
        let header = layout.load_header()?;
        let mvk = header.unlock_with_wrapping_key(slot_uuid, &kek)?;
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
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        Ok(catalog.root_folder_id.to_string())
    }

    /// Registers a 32-byte hardware-backed wrapping key (Android Keystore) and returns slot_id.
    pub fn add_hardware_keystore_slot(
        &self,
        wrapping_key_bytes: Vec<u8>,
    ) -> Result<String, FfiVaultError> {
        let raw_kek: [u8; KEY_LEN] = wrapping_key_bytes
            .try_into()
            .map_err(|_| FfiVaultError::InvalidWrappingKeyLength)?;
        let kek = KeyWrappingKey::from_bytes(raw_kek);

        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let mvk = guard.mvk.take().ok_or(FfiVaultError::VaultLocked)?;
        let res = guard.header.add_hardware_slot(&mvk, &kek);
        guard.mvk = Some(mvk);
        let slot_id = res?;
        guard.layout.write_header_pair(&guard.header)?;
        Ok(slot_id.to_string())
    }

    /// Generates and registers a new 24-word Recovery Kit slot in the dual vault header.
    pub fn add_recovery_kit_slot(&self) -> Result<String, FfiVaultError> {
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
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
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
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
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;

        let id = catalog.create_folder(parent_uuid, name, now_unix_ms)?;
        inner.layout.save_catalog(mvk, catalog)?;
        Ok(id.to_string())
    }

    /// Toggles pinned status on a folder for quick access on the Dark Cockpit Overview.
    pub fn set_folder_pinned(&self, folder_id: String, pinned: bool) -> Result<(), FfiVaultError> {
        let target_uuid = parse_uuid(&folder_id)?;
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;

        let folder = catalog
            .folders
            .get_mut(&target_uuid)
            .ok_or(FfiVaultError::FolderNotFound(folder_id))?;
        folder.pinned = pinned;
        catalog.catalog_revision = catalog.catalog_revision.saturating_add(1);
        inner.layout.save_catalog(mvk, catalog)?;
        Ok(())
    }

    /// Toggles Blur Shield on a folder inside the unlocked vault.
    pub fn set_folder_blur_shield(
        &self,
        folder_id: String,
        blur_shield: bool,
    ) -> Result<(), FfiVaultError> {
        let target_uuid = parse_uuid(&folder_id)?;
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;

        let folder = catalog
            .folders
            .get_mut(&target_uuid)
            .ok_or(FfiVaultError::FolderNotFound(folder_id))?;
        folder.blur_shield = blur_shield;
        catalog.catalog_revision = catalog.catalog_revision.saturating_add(1);
        inner.layout.save_catalog(mvk, catalog)?;
        Ok(())
    }

    /// Toggles favorite status on a media item.
    pub fn toggle_favorite(&self, media_id: String) -> Result<bool, FfiVaultError> {
        let target_uuid = parse_uuid(&media_id)?;
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;

        let item = catalog
            .media
            .get_mut(&target_uuid)
            .ok_or(FfiVaultError::MediaNotFound(media_id))?;
        item.favorite = !item.favorite;
        let new_state = item.favorite;
        catalog.catalog_revision = catalog.catalog_revision.saturating_add(1);
        inner.layout.save_catalog(mvk, catalog)?;
        Ok(new_state)
    }

    /// Returns folder breadcrumbs from Root down to `folder_id`.
    pub fn get_folder_breadcrumbs(
        &self,
        folder_id: String,
    ) -> Result<Vec<FfiFolderDto>, FfiVaultError> {
        let target_uuid = parse_uuid(&folder_id)?;
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        Ok(catalog
            .breadcrumbs(target_uuid)
            .into_iter()
            .map(|f| folder_to_dto(catalog, f))
            .collect())
    }

    /// Lists decrypted subfolder and media metadata for `folder_id` in RAM.
    pub fn list_folder_contents(
        &self,
        folder_id: String,
    ) -> Result<FfiFolderContentsDto, FfiVaultError> {
        let target_uuid = parse_uuid(&folder_id)?;
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let (subfolders, items) = catalog.list_folder_contents(target_uuid);

        Ok(FfiFolderContentsDto {
            folder_id,
            subfolders: subfolders
                .into_iter()
                .map(|f| folder_to_dto(catalog, f))
                .collect(),
            media: items.into_iter().map(media_to_dto).collect(),
        })
    }

    /// Lists all active media sorted newest-first for the unified Gallery screen.
    pub fn list_all_media_timeline(&self) -> Result<Vec<FfiMediaDto>, FfiVaultError> {
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        Ok(catalog
            .timeline_media()
            .into_iter()
            .map(media_to_dto)
            .collect())
    }

    /// Returns aggregate Cockpit metrics and storage distribution by category.
    pub fn vault_metrics(&self) -> Result<FfiVaultMetricsDto, FfiVaultError> {
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let m = catalog.compute_metrics();
        Ok(FfiVaultMetricsDto {
            vault_id: guard.header.vault_id.to_string(),
            header_revision: guard.header.revision,
            folder_count: m.folder_count,
            total_media: m.total_media,
            total_bytes: m.total_bytes,
            photo_count: m.photo_count,
            photo_bytes: m.photo_bytes,
            video_count: m.video_count,
            video_bytes: m.video_bytes,
            raw_count: m.raw_count,
            raw_bytes: m.raw_bytes,
            doc_count: m.doc_count,
            doc_bytes: m.doc_bytes,
            audio_count: m.audio_count,
            audio_bytes: m.audio_bytes,
            thumb_pack_bytes: m.thumb_pack_bytes,
            trashed_count: m.trashed_count,
            trashed_bytes: m.trashed_bytes,
        })
    }

    /// Imports an in-memory media stream (from Android Photo Picker / SAF InputStream) directly into the vault.
    #[allow(clippy::too_many_arguments)]
    pub fn import_bytes_item(
        &self,
        target_parent_id: String,
        relative_folder_segments: Vec<String>,
        file_name: String,
        bytes: Vec<u8>,
        dedup_policy: FfiDedupPolicy,
        captured_at_unix_ms: Option<u64>,
        now_unix_ms: u64,
    ) -> Result<FfiSingleImportResultDto, FfiVaultError> {
        let parent_uuid = parse_uuid(&target_parent_id)?;
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;

        let res = ImportPipeline::import_bytes_item(
            &inner.layout,
            mvk,
            catalog,
            parent_uuid,
            &relative_folder_segments,
            &file_name,
            &bytes,
            dedup_policy.into(),
            captured_at_unix_ms,
            now_unix_ms,
        )?;

        Ok(FfiSingleImportResultDto {
            media_id: res.media_id.to_string(),
            target_folder_id: res.target_folder_id.to_string(),
            deduplicated_skip: res.deduplicated_skip,
            deduplicated_link: res.deduplicated_link,
            bytes_encrypted: res.bytes_encrypted,
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
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
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
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
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
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
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
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
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
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
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

    /// Configures an isolated Decoy Vault with an independent MVK and separate catalog.
    pub fn configure_decoy_vault(
        &self,
        decoy_passphrase: String,
        now_unix_ms: u64,
    ) -> Result<String, FfiVaultError> {
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        if guard.state != VaultSecurityState::UnlockedFull {
            return Err(FfiVaultError::VaultLocked);
        }
        let decoy_mvk = MasterVaultKey::generate();
        let decoy_secret = SecretString::from(decoy_passphrase);
        let slot_id = guard.header.add_decoy_slot(&decoy_secret, &decoy_mvk)?;
        guard.layout.write_header_pair(&guard.header)?;

        let decoy_catalog = VaultCatalog::new(guard.header.vault_id, now_unix_ms);
        guard
            .layout
            .save_decoy_catalog(&decoy_mvk, &decoy_catalog)?;
        Ok(slot_id.to_string())
    }

    /// Enters Safe Presentation Lock mode (disables folder exit until re-auth).
    pub fn enter_safe_presentation(&self) -> Result<(), FfiVaultError> {
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        if guard.state == VaultSecurityState::UnlockedFull {
            guard.state = VaultSecurityState::UnlockedSafePresentation;
        }
        Ok(())
    }

    /// Exits Safe Presentation Lock back to UnlockedFull.
    pub fn exit_safe_presentation(&self) -> Result<(), FfiVaultError> {
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        if guard.state == VaultSecurityState::UnlockedSafePresentation {
            guard.state = VaultSecurityState::UnlockedFull;
        }
        Ok(())
    }

    /// Moves a media item into the encrypted 30-day Trash.
    pub fn move_to_trash(&self, media_id: String, now_unix_ms: u64) -> Result<(), FfiVaultError> {
        let uuid = parse_uuid(&media_id)?;
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;
        catalog.move_to_trash(uuid, now_unix_ms)?;
        save_active_catalog(inner.state, &inner.layout, mvk, catalog)?;
        Ok(())
    }

    /// Restores a trashed media item back into active Gallery/Folders.
    pub fn restore_from_trash(&self, media_id: String) -> Result<(), FfiVaultError> {
        let uuid = parse_uuid(&media_id)?;
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;
        catalog.restore_from_trash(uuid)?;
        save_active_catalog(inner.state, &inner.layout, mvk, catalog)?;
        Ok(())
    }

    /// Lists media currently in the encrypted Trash.
    pub fn list_trashed_media(&self) -> Result<Vec<FfiMediaDto>, FfiVaultError> {
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        Ok(catalog
            .list_trashed_media()
            .into_iter()
            .map(media_to_dto)
            .collect())
    }

    /// Cryptographically shreds a media blob and purges its catalog entry.
    pub fn shred_media(&self, media_id: String) -> Result<(), FfiVaultError> {
        let uuid = parse_uuid(&media_id)?;
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;
        catalog.shred_media(&inner.layout, uuid)?;
        save_active_catalog(inner.state, &inner.layout, mvk, catalog)?;
        Ok(())
    }

    /// Purges all trashed items older than `retention_days`.
    pub fn purge_expired_trash(
        &self,
        retention_days: u32,
        now_unix_ms: u64,
    ) -> Result<u64, FfiVaultError> {
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;
        let purged = catalog.purge_expired_trash(&inner.layout, retention_days, now_unix_ms)?;
        if purged > 0 {
            save_active_catalog(inner.state, &inner.layout, mvk, catalog)?;
            let _ = inner.layout.append_audit_event(
                mvk,
                inner.header.vault_id,
                AuditLogEntry {
                    timestamp_unix_ms: now_unix_ms,
                    kind: AuditEventKind::TrashPurged,
                    detail: format!("Purged {purged} expired trashed items"),
                },
            );
        }
        Ok(purged)
    }

    /// Moves a media item into a different encrypted folder.
    pub fn move_media_to_folder(
        &self,
        media_id: String,
        dest_folder_id: String,
    ) -> Result<(), FfiVaultError> {
        let media_uuid = parse_uuid(&media_id)?;
        let dest_uuid = parse_uuid(&dest_folder_id)?;
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;
        catalog.move_media(media_uuid, dest_uuid)?;
        save_active_catalog(inner.state, &inner.layout, mvk, catalog)?;
        Ok(())
    }

    /// Renames a non-root encrypted folder.
    pub fn rename_folder(&self, folder_id: String, new_name: String) -> Result<(), FfiVaultError> {
        let folder_uuid = parse_uuid(&folder_id)?;
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;
        catalog.rename_folder(folder_uuid, new_name)?;
        save_active_catalog(inner.state, &inner.layout, mvk, catalog)?;
        Ok(())
    }

    /// Updates tags and encrypted Markdown note for a media item.
    pub fn update_media_tags_and_note(
        &self,
        media_id: String,
        tags: Vec<String>,
        note_markdown: Option<String>,
    ) -> Result<(), FfiVaultError> {
        let media_uuid = parse_uuid(&media_id)?;
        let mut guard = self.inner.write().map_err(|_| FfiVaultError::VaultLocked)?;
        let inner = &mut *guard;
        let mvk = inner.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = inner.catalog.as_mut().ok_or(FfiVaultError::VaultLocked)?;
        catalog.update_media_tags_and_note(media_uuid, tags, note_markdown)?;
        save_active_catalog(inner.state, &inner.layout, mvk, catalog)?;
        Ok(())
    }

    /// Offline search across names, tags, Markdown notes, EXIF camera, and MIME types.
    pub fn search_media(&self, query: String) -> Result<Vec<FfiMediaDto>, FfiVaultError> {
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        Ok(catalog
            .search_media(&query)
            .into_iter()
            .map(media_to_dto)
            .collect())
    }

    /// Finds groups of visually similar images by 64-bit `dHash` Hamming distance.
    pub fn find_similar_by_dhash(
        &self,
        max_hamming: u32,
    ) -> Result<Vec<FfiSimilarGroupDto>, FfiVaultError> {
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        Ok(catalog
            .find_similar_by_dhash(max_hamming)
            .into_iter()
            .map(|g| FfiSimilarGroupDto {
                anchor_dhash_hex: format!("{:016x}", g.anchor_dhash),
                media_ids: g.media_ids.into_iter().map(|id| id.to_string()).collect(),
            })
            .collect())
    }

    /// Decrypts media in RAM and strips EXIF/GPS/XMP metadata for Clean Export.
    pub fn clean_export_media_bytes(&self, media_id: String) -> Result<Vec<u8>, FfiVaultError> {
        let uuid = parse_uuid(&media_id)?;
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let mvk = guard.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let catalog = guard.catalog.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let entry = catalog
            .media
            .get(&uuid)
            .ok_or(FfiVaultError::MediaNotFound(media_id))?;
        let wrapped: [u8; WRAPPED_FEK_LEN] = entry
            .wrapped_fek
            .as_slice()
            .try_into()
            .map_err(|_| meshvault_crypto::CryptoError::AuthenticationFailed)?;
        let fek = unwrap_fek(mvk, uuid, &wrapped)?;

        let blob_file = fs::File::open(guard.layout.blob_path(uuid))?;
        let mut reader = ChunkedBlobReader::open(blob_file)?;
        let mut plain = Vec::with_capacity(entry.plaintext_size as usize);
        reader.decrypt_all_to(&fek, &mut plain)?;
        let cleaned = strip_metadata_for_clean_export(&entry.mime_type, &plain);
        plain.zeroize();
        Ok(cleaned)
    }

    /// Lists decrypted security audit log entries in RAM.
    pub fn list_audit_events(&self) -> Result<Vec<FfiAuditEventDto>, FfiVaultError> {
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let mvk = guard.mvk.as_ref().ok_or(FfiVaultError::VaultLocked)?;
        let events = guard.layout.load_audit_events(mvk, guard.header.vault_id)?;
        Ok(events
            .into_iter()
            .map(|e| FfiAuditEventDto {
                timestamp_unix_ms: e.timestamp_unix_ms,
                kind: format!("{:?}", e.kind),
                detail: e.detail,
            })
            .collect())
    }

    /// Runs `MeshVault Doctor` diagnostics over header slots, catalog, packs, and WAL.
    pub fn doctor_report(&self) -> Result<FfiDoctorReportDto, FfiVaultError> {
        let guard = self.inner.read().map_err(|_| FfiVaultError::VaultLocked)?;
        let report = guard.layout.doctor_report(guard.catalog.as_ref());
        Ok(FfiDoctorReportDto {
            primary_header_valid: report.primary_header_valid,
            backup_header_valid: report.backup_header_valid,
            header_revision: report.header_revision,
            key_slot_count: report.key_slot_count,
            decoy_configured: report.decoy_configured,
            media_count: report.media_count,
            trashed_count: report.trashed_count,
            missing_blobs_count: report.missing_blobs_count,
            thumb_pack_count: report.thumb_pack_count,
            wal_pending: report.wal_pending,
        })
    }
}

fn save_active_catalog(
    state: VaultSecurityState,
    layout: &VaultLayout,
    mvk: &MasterVaultKey,
    catalog: &VaultCatalog,
) -> Result<(), meshvault_storage::StorageError> {
    if state == VaultSecurityState::UnlockedDecoy {
        layout.save_decoy_catalog(mvk, catalog)
    } else {
        layout.save_catalog(mvk, catalog)
    }
}

fn folder_to_dto(catalog: &VaultCatalog, f: &meshvault_storage::FolderNode) -> FfiFolderDto {
    let (subfolders, items) = catalog.list_folder_contents(f.id);
    let total_bytes: u64 = items.iter().map(|m| m.plaintext_size).sum();
    FfiFolderDto {
        id: f.id.to_string(),
        parent_id: f.parent_id.map(|p| p.to_string()),
        name: f.name.clone(),
        blur_shield: f.blur_shield,
        pinned: f.pinned,
        subfolder_count: subfolders.len() as u64,
        media_count: items.len() as u64,
        total_bytes,
        created_at_unix_ms: f.created_at_unix_ms,
    }
}

fn media_to_dto(m: &meshvault_storage::MediaEntry) -> FfiMediaDto {
    FfiMediaDto {
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
        tags: m.tags.clone(),
        captured_at_unix_ms: m.captured_at_unix_ms,
        imported_at_unix_ms: m.imported_at_unix_ms,
    }
}

fn parse_uuid(s: &str) -> Result<Uuid, FfiVaultError> {
    Uuid::parse_str(s).map_err(|_| FfiVaultError::InvalidUuid(s.to_string()))
}
