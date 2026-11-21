use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshvault_crypto::{
    unwrap_fek, wrap_fek, ChunkedBlobReader, CryptoError, FileEncryptionKey, MasterVaultKey,
    VaultHeader, TAG_LEN, WRAPPED_FEK_LEN, XNONCE_LEN,
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

/// Magic bytes for a 4 MiB encrypted thumbnail pack (`thumbs/pack_<id>.mvt`).
pub const THUMB_PACK_MAGIC: [u8; 4] = *b"MVT1";

/// Fixed 20-byte prelude at offset 0 of every `.mvt` thumbnail pack.
pub const THUMB_PACK_PRELUDE_LEN: usize = 20;

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

    #[error("invalid thumbnail pack: {0}")]
    InvalidThumbPack(String),

    #[error("folder not found: {0}")]
    FolderNotFound(Uuid),

    #[error("media item not found: {0}")]
    MediaNotFound(Uuid),
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

    pub fn decoy_catalog_path(&self) -> PathBuf {
        self.root.join("catalog").join("decoy.mvc")
    }

    pub fn audit_log_path(&self) -> PathBuf {
        self.root.join("catalog").join("audit.mva")
    }

    pub fn lockout_state_path(&self) -> PathBuf {
        self.root.join("wal").join("lockout.json")
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    pub fn blob_path(&self, file_id: Uuid) -> PathBuf {
        let hex = file_id.simple().to_string();
        let prefix = &hex[..2];
        self.blobs_dir().join(prefix).join(format!("{hex}.mvb"))
    }

    pub fn blob_part_path(&self, file_id: Uuid) -> PathBuf {
        let hex = file_id.simple().to_string();
        let prefix = &hex[..2];
        self.blobs_dir()
            .join(prefix)
            .join(format!("{hex}.mvb.part"))
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

    /// Seals and atomically writes `catalog/tree.mvc`.
    pub fn save_catalog(
        &self,
        mvk: &MasterVaultKey,
        catalog: &VaultCatalog,
    ) -> Result<(), StorageError> {
        self.ensure_directories()?;
        let sealed = catalog.seal(mvk)?;
        atomic_write_file(&self.catalog_path(), &sealed)?;
        Ok(())
    }

    /// Reads and authenticates `catalog/tree.mvc` into RAM.
    pub fn load_catalog(&self, mvk: &MasterVaultKey) -> Result<VaultCatalog, StorageError> {
        let sealed = fs::read(self.catalog_path())?;
        VaultCatalog::open(mvk, &sealed)
    }

    /// Seals and atomically writes the isolated Decoy Vault catalog (`catalog/decoy.mvc`).
    pub fn save_decoy_catalog(
        &self,
        decoy_mvk: &MasterVaultKey,
        catalog: &VaultCatalog,
    ) -> Result<(), StorageError> {
        self.ensure_directories()?;
        let sealed = catalog.seal(decoy_mvk)?;
        atomic_write_file(&self.decoy_catalog_path(), &sealed)?;
        Ok(())
    }

    /// Reads and authenticates `catalog/decoy.mvc` using the decoy MVK.
    pub fn load_decoy_catalog(
        &self,
        decoy_mvk: &MasterVaultKey,
    ) -> Result<VaultCatalog, StorageError> {
        let sealed = fs::read(self.decoy_catalog_path())?;
        VaultCatalog::open(decoy_mvk, &sealed)
    }

    /// Appends an entry to the encrypted local security audit log (`catalog/audit.mva`).
    pub fn append_audit_event(
        &self,
        mvk: &MasterVaultKey,
        vault_id: Uuid,
        entry: AuditLogEntry,
    ) -> Result<(), StorageError> {
        self.ensure_directories()?;
        let mut entries = self.load_audit_events(mvk, vault_id).unwrap_or_default();
        entries.push(entry);
        if entries.len() > 2000 {
            let drain = entries.len() - 2000;
            entries.drain(0..drain);
        }
        let sealed = seal_audit_log(mvk, vault_id, &entries)?;
        atomic_write_file(&self.audit_log_path(), &sealed)?;
        Ok(())
    }

    /// Reads and decrypts the local security audit log into RAM.
    pub fn load_audit_events(
        &self,
        mvk: &MasterVaultKey,
        vault_id: Uuid,
    ) -> Result<Vec<AuditLogEntry>, StorageError> {
        let path = self.audit_log_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let sealed = fs::read(path)?;
        open_audit_log(mvk, vault_id, &sealed)
    }

    /// Records a failed unlock attempt and returns the recommended exponential backoff in seconds.
    pub fn record_failed_unlock(&self, now_unix_ms: u64) -> Result<BruteForceState, StorageError> {
        self.ensure_directories()?;
        let mut state = self.load_lockout_state().unwrap_or_default();
        state.failed_attempts = state.failed_attempts.saturating_add(1);
        state.last_failed_unix_ms = now_unix_ms;
        state.backoff_seconds = compute_backoff_seconds(state.failed_attempts);
        let json = serde_json::to_vec(&state)?;
        atomic_write_file(&self.lockout_state_path(), &json)?;
        Ok(state)
    }

    /// Resets the brute-force delay counter after a successful authentication.
    pub fn reset_failed_unlocks(&self) -> Result<(), StorageError> {
        let path = self.lockout_state_path();
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Reads current lockout delay state without touching the catalog.
    pub fn load_lockout_state(&self) -> Result<BruteForceState, StorageError> {
        let path = self.lockout_state_path();
        if !path.exists() {
            return Ok(BruteForceState::default());
        }
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Builds a diagnostic report (`MeshVault Doctor`) for header slots, blobs, packs, and trash.
    pub fn doctor_report(&self, catalog: Option<&VaultCatalog>) -> VaultDoctorReport {
        let primary_ok = fs::read(self.primary_header_path())
            .ok()
            .and_then(|b| VaultHeader::from_bytes(&b).ok());
        let backup_ok = fs::read(self.backup_header_path())
            .ok()
            .and_then(|b| VaultHeader::from_bytes(&b).ok());
        let header = VaultHeader::select_latest_valid(
            fs::read(self.primary_header_path()).ok().as_deref(),
            fs::read(self.backup_header_path()).ok().as_deref(),
        )
        .ok();

        let (key_slot_count, decoy_configured, header_revision) = match &header {
            Some(h) => (
                h.slots.len() as u32,
                h.slots
                    .iter()
                    .any(|s| s.slot_type == meshvault_crypto::SlotType::DecoyPassphrase),
                h.revision,
            ),
            None => (0, false, 0),
        };

        let (media_count, trashed_count, missing_blobs_count, thumb_pack_count) = match catalog {
            Some(cat) => {
                let metrics = cat.compute_metrics();
                let missing = cat
                    .media
                    .keys()
                    .filter(|id| !self.blob_path(**id).exists())
                    .count() as u64;
                (
                    metrics.total_media,
                    metrics.trashed_count,
                    missing,
                    cat.thumb_packs.len() as u64,
                )
            }
            None => (0, 0, 0, 0),
        };

        VaultDoctorReport {
            primary_header_valid: primary_ok.is_some(),
            backup_header_valid: backup_ok.is_some(),
            header_revision,
            key_slot_count,
            decoy_configured,
            media_count,
            trashed_count,
            missing_blobs_count,
            thumb_pack_count,
            wal_pending: self.import_wal_path().exists(),
        }
    }

    /// Appends an encrypted thumbnail into a 4 MiB `.mvt` pack and returns its `ThumbLocator`.
    pub fn append_thumbnail(
        &self,
        mvk: &MasterVaultKey,
        catalog: &mut VaultCatalog,
        media_id: Uuid,
        thumb_bytes: &[u8],
    ) -> Result<ThumbLocator, StorageError> {
        self.ensure_directories()?;

        let active_pack_id = catalog
            .thumb_packs
            .iter()
            .find(|(_, meta)| (meta.payload_bytes as usize) < THUMB_PACK_TARGET_BYTES)
            .map(|(id, _)| *id);

        let (pack_id, pack_fek) = match active_pack_id {
            Some(id) => {
                let meta = catalog
                    .thumb_packs
                    .get(&id)
                    .ok_or_else(|| StorageError::InvalidThumbPack("missing pack meta".into()))?;
                let wrapped: [u8; WRAPPED_FEK_LEN] =
                    meta.wrapped_fek.as_slice().try_into().map_err(|_| {
                        StorageError::InvalidThumbPack("invalid wrapped FEK".into())
                    })?;
                let fek = unwrap_fek(mvk, id, &wrapped)?;
                (id, fek)
            }
            None => {
                let id = Uuid::new_v4();
                let fek = FileEncryptionKey::generate();
                let wrapped = wrap_fek(mvk, id, &fek)?;
                let pack_path = self.thumb_pack_path(id);
                let mut prelude = [0u8; THUMB_PACK_PRELUDE_LEN];
                prelude[0..4].copy_from_slice(&THUMB_PACK_MAGIC);
                prelude[4..20].copy_from_slice(id.as_bytes());
                atomic_write_file(&pack_path, &prelude)?;

                catalog.thumb_packs.insert(
                    id,
                    ThumbPackMeta {
                        pack_id: id,
                        wrapped_fek: wrapped.to_vec(),
                        payload_bytes: THUMB_PACK_PRELUDE_LEN as u32,
                    },
                );
                (id, fek)
            }
        };

        let pack_path = self.thumb_pack_path(pack_id);
        let mut file = OpenOptions::new().read(true).write(true).open(&pack_path)?;
        let file_len = file.seek(SeekFrom::End(0))?;
        let offset = u32::try_from(file_len)
            .map_err(|_| StorageError::InvalidThumbPack("pack offset overflow".into()))?;

        let mut nonce_bytes = [0u8; XNONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = thumb_record_aad(pack_id, offset, media_id);

        let cipher = XChaCha20Poly1305::new_from_slice(pack_fek.expose())
            .map_err(|_| StorageError::InvalidThumbPack("invalid pack FEK".into()))?;
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: thumb_bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        let total_record_len = u32::try_from(XNONCE_LEN + ciphertext.len())
            .map_err(|_| StorageError::InvalidThumbPack("thumbnail too large".into()))?;

        file.write_all(&nonce_bytes)?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;

        if let Some(meta) = catalog.thumb_packs.get_mut(&pack_id) {
            meta.payload_bytes = offset.saturating_add(total_record_len);
        }

        Ok(ThumbLocator {
            pack_id,
            offset,
            len: total_record_len,
        })
    }

    /// Decrypts a thumbnail directly from its 4 MiB `.mvt` pack into RAM (zero disk plaintext).
    pub fn read_thumbnail(
        &self,
        mvk: &MasterVaultKey,
        catalog: &VaultCatalog,
        media_id: Uuid,
        locator: ThumbLocator,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let meta = catalog
            .thumb_packs
            .get(&locator.pack_id)
            .ok_or_else(|| StorageError::InvalidThumbPack("unknown thumb pack id".into()))?;
        let wrapped: [u8; WRAPPED_FEK_LEN] = meta
            .wrapped_fek
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::InvalidThumbPack("invalid wrapped FEK".into()))?;
        let pack_fek = unwrap_fek(mvk, locator.pack_id, &wrapped)?;

        if (locator.len as usize) < XNONCE_LEN + TAG_LEN {
            return Err(StorageError::InvalidThumbPack(
                "thumbnail locator shorter than AEAD overhead".into(),
            ));
        }

        let pack_path = self.thumb_pack_path(locator.pack_id);
        let mut file = fs::File::open(pack_path)?;
        let mut prelude = [0u8; THUMB_PACK_PRELUDE_LEN];
        file.read_exact(&mut prelude)?;
        if prelude[0..4] != THUMB_PACK_MAGIC || prelude[4..20] != *locator.pack_id.as_bytes() {
            return Err(StorageError::InvalidThumbPack(
                "pack prelude mismatch".into(),
            ));
        }

        file.seek(SeekFrom::Start(u64::from(locator.offset)))?;
        let mut record = vec![0u8; locator.len as usize];
        file.read_exact(&mut record)?;

        let nonce = XNonce::from_slice(&record[..XNONCE_LEN]);
        let ciphertext = &record[XNONCE_LEN..];
        let aad = thumb_record_aad(locator.pack_id, locator.offset, media_id);

        let cipher = XChaCha20Poly1305::new_from_slice(pack_fek.expose())
            .map_err(|_| StorageError::InvalidThumbPack("invalid pack FEK".into()))?;
        let plain = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(Zeroizing::new(plain))
    }

    /// Runs Vault Scrub across all active media blobs, verifying every chunk Poly1305 tag.
    pub fn scrub_vault(
        &self,
        mvk: &MasterVaultKey,
        catalog: &VaultCatalog,
    ) -> Result<ScrubReport, StorageError> {
        let mut report = ScrubReport::default();

        for (media_id, entry) in &catalog.media {
            let blob_path = self.blob_path(*media_id);
            if !blob_path.exists() {
                report.missing_blobs.push(*media_id);
                continue;
            }

            let wrapped: [u8; WRAPPED_FEK_LEN] = match entry.wrapped_fek.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    report.corrupted_blobs.push(*media_id);
                    continue;
                }
            };
            let fek = match unwrap_fek(mvk, *media_id, &wrapped) {
                Ok(k) => k,
                Err(_) => {
                    report.corrupted_blobs.push(*media_id);
                    continue;
                }
            };

            let file = match fs::File::open(&blob_path) {
                Ok(f) => f,
                Err(_) => {
                    report.corrupted_blobs.push(*media_id);
                    continue;
                }
            };

            match ChunkedBlobReader::open(file) {
                Ok(mut reader) => match reader.verify_all_chunks(&fek) {
                    Ok(plain_bytes) => {
                        report.checked_blobs += 1;
                        report.checked_chunks += reader.total_chunks();
                        report.verified_bytes += plain_bytes;
                    }
                    Err(_) => {
                        report.checked_blobs += 1;
                        report.corrupted_blobs.push(*media_id);
                    }
                },
                Err(_) => {
                    report.checked_blobs += 1;
                    report.corrupted_blobs.push(*media_id);
                }
            }
        }

        Ok(report)
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

/// Metadata for a 4 MiB encrypted thumbnail pack (`thumbs/pack_*.mvt`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThumbPackMeta {
    pub pack_id: Uuid,
    pub wrapped_fek: Vec<u8>,
    pub payload_bytes: u32,
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
    #[serde(default)]
    pub linked_folder_ids: Vec<Uuid>,
    pub original_name: String,
    pub mime_type: String,
    pub kind: MediaKind,
    pub plaintext_size: u64,
    pub dedup_blake3: [u8; 32],
    pub phash: Option<u64>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub exif_camera: Option<String>,
    #[serde(default)]
    pub micro_thumb: Option<Vec<u8>>,
    pub wrapped_fek: Vec<u8>,
    pub thumb: Option<ThumbLocator>,
    pub tags: Vec<String>,
    #[serde(default)]
    pub note_markdown: Option<String>,
    pub favorite: bool,
    pub trashed_at_unix_ms: Option<u64>,
    pub captured_at_unix_ms: Option<u64>,
    pub imported_at_unix_ms: u64,
}

impl MediaEntry {
    pub fn has_valid_wrapped_fek_len(&self) -> bool {
        self.wrapped_fek.len() == WRAPPED_FEK_LEN
    }

    pub fn is_in_folder(&self, target_folder_id: Uuid) -> bool {
        self.trashed_at_unix_ms.is_none()
            && (self.folder_id == target_folder_id
                || self.linked_folder_ids.contains(&target_folder_id))
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
    #[serde(default)]
    pub thumb_packs: BTreeMap<Uuid, ThumbPackMeta>,
    #[serde(default)]
    pub dedup_index: BTreeMap<String, Uuid>,
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
            thumb_packs: BTreeMap::new(),
            dedup_index: BTreeMap::new(),
        }
    }

    /// Finds an existing direct child folder by exact name under `parent_id`.
    pub fn find_child_folder(&self, parent_id: Uuid, name: &str) -> Option<Uuid> {
        self.folders
            .values()
            .find(|f| f.parent_id == Some(parent_id) && f.name == name)
            .map(|f| f.id)
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

    /// Idempotently walks or creates nested subfolders (`Incremental Folder Merge`).
    pub fn ensure_folder_path(
        &mut self,
        start_parent_id: Uuid,
        segments: &[&str],
        created_at_unix_ms: u64,
    ) -> Result<Uuid, StorageError> {
        if !self.folders.contains_key(&start_parent_id) {
            return Err(StorageError::FolderNotFound(start_parent_id));
        }
        let mut current = start_parent_id;
        for seg in segments {
            if seg.is_empty() {
                continue;
            }
            if let Some(existing) = self.find_child_folder(current, seg) {
                current = existing;
            } else {
                current = self.create_folder(current, (*seg).to_string(), created_at_unix_ms)?;
            }
        }
        Ok(current)
    }

    /// Inserts a media entry and updates the keyed BLAKE3 deduplication index.
    pub fn insert_media(&mut self, entry: MediaEntry) {
        let dedup_key = hex_32(&entry.dedup_blake3);
        let id = entry.id;
        self.dedup_index.entry(dedup_key).or_insert(id);
        self.media.insert(id, entry);
        self.catalog_revision = self.catalog_revision.saturating_add(1);
    }

    /// Looks up an existing media entry matching a vault-scoped keyed BLAKE3 hash.
    pub fn find_by_dedup_hash(&self, dedup_hash: &[u8; 32]) -> Option<Uuid> {
        self.dedup_index.get(&hex_32(dedup_hash)).copied()
    }

    /// Lists direct subfolders and active media items inside `folder_id`.
    pub fn list_folder_contents(&self, folder_id: Uuid) -> (Vec<&FolderNode>, Vec<&MediaEntry>) {
        let mut subfolders: Vec<&FolderNode> = self
            .folders
            .values()
            .filter(|f| f.parent_id == Some(folder_id))
            .collect();
        subfolders.sort_by(|a, b| a.name.cmp(&b.name));

        let mut items: Vec<&MediaEntry> = self
            .media
            .values()
            .filter(|m| m.is_in_folder(folder_id))
            .collect();
        items.sort_by(|a, b| a.original_name.cmp(&b.original_name));

        (subfolders, items)
    }

    /// Returns folder hierarchy breadcrumbs from Root down to `folder_id`.
    pub fn breadcrumbs(&self, folder_id: Uuid) -> Vec<&FolderNode> {
        let mut chain = Vec::new();
        let mut current = Some(folder_id);
        let mut guard = 0usize;
        while let Some(id) = current {
            if guard > 128 {
                break;
            }
            guard += 1;
            let Some(node) = self.folders.get(&id) else {
                break;
            };
            chain.push(node);
            current = node.parent_id;
        }
        chain.reverse();
        chain
    }

    /// Returns active non-trashed media sorted newest-first for the chronological Gallery timeline.
    pub fn timeline_media(&self) -> Vec<&MediaEntry> {
        let mut items: Vec<&MediaEntry> = self
            .media
            .values()
            .filter(|m| m.trashed_at_unix_ms.is_none())
            .collect();
        items.sort_by(|a, b| {
            let ta = a.captured_at_unix_ms.unwrap_or(a.imported_at_unix_ms);
            let tb = b.captured_at_unix_ms.unwrap_or(b.imported_at_unix_ms);
            tb.cmp(&ta)
                .then_with(|| a.original_name.cmp(&b.original_name))
        });
        items
    }

    /// Moves a media entry into the encrypted 30-day Trash.
    pub fn move_to_trash(&mut self, media_id: Uuid, now_unix_ms: u64) -> Result<(), StorageError> {
        let item = self
            .media
            .get_mut(&media_id)
            .ok_or(StorageError::MediaNotFound(media_id))?;
        item.trashed_at_unix_ms = Some(now_unix_ms);
        self.catalog_revision = self.catalog_revision.saturating_add(1);
        Ok(())
    }

    /// Restores a media entry from Trash back into active Gallery/Folders.
    pub fn restore_from_trash(&mut self, media_id: Uuid) -> Result<(), StorageError> {
        let item = self
            .media
            .get_mut(&media_id)
            .ok_or(StorageError::MediaNotFound(media_id))?;
        item.trashed_at_unix_ms = None;
        self.catalog_revision = self.catalog_revision.saturating_add(1);
        Ok(())
    }

    /// Lists media currently in the encrypted Trash sorted newest-trashed first.
    pub fn list_trashed_media(&self) -> Vec<&MediaEntry> {
        let mut items: Vec<&MediaEntry> = self
            .media
            .values()
            .filter(|m| m.trashed_at_unix_ms.is_some())
            .collect();
        items.sort_by(|a, b| {
            b.trashed_at_unix_ms
                .cmp(&a.trashed_at_unix_ms)
                .then_with(|| a.original_name.cmp(&b.original_name))
        });
        items
    }

    /// Cryptographically shreds a media item: deletes its `.mvb` blob, clears dedup index, and removes metadata.
    pub fn shred_media(
        &mut self,
        layout: &VaultLayout,
        media_id: Uuid,
    ) -> Result<(), StorageError> {
        let mut entry = self
            .media
            .remove(&media_id)
            .ok_or(StorageError::MediaNotFound(media_id))?;
        entry.wrapped_fek.fill(0);

        let dedup_key = hex_32(&entry.dedup_blake3);
        if self.dedup_index.get(&dedup_key) == Some(&media_id) {
            self.dedup_index.remove(&dedup_key);
        }

        let blob = layout.blob_path(media_id);
        if blob.exists() {
            fs::remove_file(blob)?;
        }
        let part = layout.blob_part_path(media_id);
        if part.exists() {
            fs::remove_file(part)?;
        }
        self.catalog_revision = self.catalog_revision.saturating_add(1);
        Ok(())
    }

    /// Permanently shreds all trashed media older than `retention_days`.
    pub fn purge_expired_trash(
        &mut self,
        layout: &VaultLayout,
        retention_days: u32,
        now_unix_ms: u64,
    ) -> Result<u64, StorageError> {
        let retention_ms = u64::from(retention_days).saturating_mul(86_400_000);
        let expired_ids: Vec<Uuid> = self
            .media
            .values()
            .filter_map(|m| {
                let trashed_at = m.trashed_at_unix_ms?;
                if now_unix_ms.saturating_sub(trashed_at) >= retention_ms {
                    Some(m.id)
                } else {
                    None
                }
            })
            .collect();

        let mut purged = 0u64;
        for id in expired_ids {
            self.shred_media(layout, id)?;
            purged += 1;
        }
        Ok(purged)
    }

    /// Moves a media item into a different folder inside the encrypted catalog.
    pub fn move_media(&mut self, media_id: Uuid, dest_folder_id: Uuid) -> Result<(), StorageError> {
        if !self.folders.contains_key(&dest_folder_id) {
            return Err(StorageError::FolderNotFound(dest_folder_id));
        }
        let item = self
            .media
            .get_mut(&media_id)
            .ok_or(StorageError::MediaNotFound(media_id))?;
        item.folder_id = dest_folder_id;
        self.catalog_revision = self.catalog_revision.saturating_add(1);
        Ok(())
    }

    /// Renames an existing non-root folder inside the encrypted catalog.
    pub fn rename_folder(
        &mut self,
        folder_id: Uuid,
        new_name: impl Into<String>,
    ) -> Result<(), StorageError> {
        if folder_id == self.root_folder_id {
            return Err(StorageError::InvalidCatalog(
                "cannot rename root folder".to_string(),
            ));
        }
        let folder = self
            .folders
            .get_mut(&folder_id)
            .ok_or(StorageError::FolderNotFound(folder_id))?;
        folder.name = new_name.into();
        self.catalog_revision = self.catalog_revision.saturating_add(1);
        Ok(())
    }

    /// Updates user tags and encrypted Markdown note attached to a media item.
    pub fn update_media_tags_and_note(
        &mut self,
        media_id: Uuid,
        tags: Vec<String>,
        note: Option<String>,
    ) -> Result<(), StorageError> {
        let item = self
            .media
            .get_mut(&media_id)
            .ok_or(StorageError::MediaNotFound(media_id))?;
        item.tags = tags;
        item.note_markdown = note;
        self.catalog_revision = self.catalog_revision.saturating_add(1);
        Ok(())
    }

    /// Offline full-text search across names, tags, Markdown notes, EXIF camera, and MIME types.
    pub fn search_media(&self, query: &str) -> Vec<&MediaEntry> {
        let q = query.trim().to_lowercase();
        let mut results: Vec<&MediaEntry> = self
            .timeline_media()
            .into_iter()
            .filter(|m| {
                if q.is_empty() {
                    return true;
                }
                m.original_name.to_lowercase().contains(&q)
                    || m.mime_type.to_lowercase().contains(&q)
                    || m.exif_camera
                        .as_ref()
                        .is_some_and(|c| c.to_lowercase().contains(&q))
                    || m.note_markdown
                        .as_ref()
                        .is_some_and(|n| n.to_lowercase().contains(&q))
                    || m.tags.iter().any(|t| t.to_lowercase().contains(&q))
            })
            .collect();
        results.sort_by(|a, b| a.original_name.cmp(&b.original_name));
        results
    }

    /// Clusters visually similar photos using Hamming distance over 64-bit `dHash` fingerprints.
    pub fn find_similar_by_dhash(&self, max_hamming: u32) -> Vec<SimilarMediaGroup> {
        let candidates: Vec<&MediaEntry> = self
            .timeline_media()
            .into_iter()
            .filter(|m| m.phash.is_some())
            .collect();
        let mut visited = vec![false; candidates.len()];
        let mut groups = Vec::new();

        for i in 0..candidates.len() {
            if visited[i] {
                continue;
            }
            let h_i = candidates[i].phash.unwrap_or(0);
            let mut cluster = vec![candidates[i].id];
            visited[i] = true;
            for j in (i + 1)..candidates.len() {
                if visited[j] {
                    continue;
                }
                let h_j = candidates[j].phash.unwrap_or(0);
                if (h_i ^ h_j).count_ones() <= max_hamming {
                    cluster.push(candidates[j].id);
                    visited[j] = true;
                }
            }
            if cluster.len() > 1 {
                groups.push(SimilarMediaGroup {
                    anchor_dhash: h_i,
                    media_ids: cluster,
                });
            }
        }
        groups
    }

    /// Computes aggregate counts and per-category byte totals for Dark Cockpit metrics and StorageDonut.
    pub fn compute_metrics(&self) -> VaultMetrics {
        let mut metrics = VaultMetrics {
            folder_count: self.folders.len() as u64,
            ..VaultMetrics::default()
        };
        for m in self.media.values() {
            if m.trashed_at_unix_ms.is_some() {
                metrics.trashed_count += 1;
                metrics.trashed_bytes = metrics.trashed_bytes.saturating_add(m.plaintext_size);
                continue;
            }
            metrics.total_media += 1;
            metrics.total_bytes = metrics.total_bytes.saturating_add(m.plaintext_size);
            match m.kind {
                MediaKind::Photo | MediaKind::Animation => {
                    metrics.photo_count += 1;
                    metrics.photo_bytes = metrics.photo_bytes.saturating_add(m.plaintext_size);
                }
                MediaKind::Video => {
                    metrics.video_count += 1;
                    metrics.video_bytes = metrics.video_bytes.saturating_add(m.plaintext_size);
                }
                MediaKind::RawPhoto => {
                    metrics.raw_count += 1;
                    metrics.raw_bytes = metrics.raw_bytes.saturating_add(m.plaintext_size);
                }
                MediaKind::DocumentPdf | MediaKind::MarkdownNote => {
                    metrics.doc_count += 1;
                    metrics.doc_bytes = metrics.doc_bytes.saturating_add(m.plaintext_size);
                }
                MediaKind::AudioNote => {
                    metrics.audio_count += 1;
                    metrics.audio_bytes = metrics.audio_bytes.saturating_add(m.plaintext_size);
                }
            }
        }
        metrics.thumb_pack_bytes = self
            .thumb_packs
            .values()
            .map(|p| u64::from(p.payload_bytes))
            .sum();
        metrics
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

/// Aggregate vault statistics displayed in Dark Cockpit MetricCard and StorageDonut.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMetrics {
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

/// Summary report emitted by background integrity checks (`Vault Scrub`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubReport {
    pub checked_blobs: u64,
    pub checked_chunks: u64,
    pub verified_bytes: u64,
    pub corrupted_blobs: Vec<Uuid>,
    pub missing_blobs: Vec<Uuid>,
}

/// Group of visually similar media items clustered by 64-bit `dHash` Hamming distance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimilarMediaGroup {
    pub anchor_dhash: u64,
    pub media_ids: Vec<Uuid>,
}

/// Security event recorded in the encrypted local audit log (`catalog/audit.mva`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventKind {
    VaultCreated,
    UnlockSuccess,
    DecoyUnlock,
    ScrubCompleted,
    TrashPurged,
    CleanExport,
    PassphraseRotated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp_unix_ms: u64,
    pub kind: AuditEventKind,
    pub detail: String,
}

/// Exponential backoff state persisted in `wal/lockout.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BruteForceState {
    pub failed_attempts: u32,
    pub last_failed_unix_ms: u64,
    pub backoff_seconds: u64,
}

/// Diagnostic snapshot produced by `MeshVault Doctor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultDoctorReport {
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

pub fn compute_backoff_seconds(failed_attempts: u32) -> u64 {
    if failed_attempts <= 2 {
        0
    } else {
        let exp = (failed_attempts - 3).min(6);
        (1u64 << exp).min(60)
    }
}

const AUDIT_MAGIC: [u8; 4] = *b"MVA1";

fn seal_audit_log(
    mvk: &MasterVaultKey,
    vault_id: Uuid,
    entries: &[AuditLogEntry],
) -> Result<Vec<u8>, StorageError> {
    let audit_key = mvk.derive_audit_log_key();
    let cipher = XChaCha20Poly1305::new_from_slice(audit_key.expose())
        .map_err(|_| StorageError::InvalidCatalog("invalid audit key".to_string()))?;
    let plain = Zeroizing::new(serde_json::to_vec(entries)?);
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut aad = Vec::with_capacity(20);
    aad.extend_from_slice(&AUDIT_MAGIC);
    aad.extend_from_slice(vault_id.as_bytes());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plain.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let mut out = Vec::with_capacity(4 + 16 + XNONCE_LEN + ciphertext.len());
    out.extend_from_slice(&AUDIT_MAGIC);
    out.extend_from_slice(vault_id.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open_audit_log(
    mvk: &MasterVaultKey,
    vault_id: Uuid,
    sealed: &[u8],
) -> Result<Vec<AuditLogEntry>, StorageError> {
    if sealed.len() < 4 + 16 + XNONCE_LEN + TAG_LEN || sealed[0..4] != AUDIT_MAGIC {
        return Err(StorageError::InvalidCatalog(
            "invalid encrypted audit log".to_string(),
        ));
    }
    if sealed[4..20] != *vault_id.as_bytes() {
        return Err(StorageError::InvalidCatalog(
            "audit log vault_id mismatch".to_string(),
        ));
    }
    let audit_key = mvk.derive_audit_log_key();
    let cipher = XChaCha20Poly1305::new_from_slice(audit_key.expose())
        .map_err(|_| StorageError::InvalidCatalog("invalid audit key".to_string()))?;
    let nonce = XNonce::from_slice(&sealed[20..20 + XNONCE_LEN]);
    let ciphertext = &sealed[20 + XNONCE_LEN..];
    let mut aad = Vec::with_capacity(20);
    aad.extend_from_slice(&AUDIT_MAGIC);
    aad.extend_from_slice(vault_id.as_bytes());
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
    Ok(serde_json::from_slice(&plain)?)
}

fn catalog_aad(vault_id: Uuid, revision: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CATALOG_AAD_PREFIX.len() + 16 + 8);
    aad.extend_from_slice(CATALOG_AAD_PREFIX);
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&revision.to_le_bytes());
    aad
}

fn thumb_record_aad(pack_id: Uuid, offset: u32, media_id: Uuid) -> [u8; 40] {
    let mut aad = [0u8; 40];
    aad[0..4].copy_from_slice(&THUMB_PACK_MAGIC);
    aad[4..20].copy_from_slice(pack_id.as_bytes());
    aad[20..24].copy_from_slice(&offset.to_le_bytes());
    aad[24..40].copy_from_slice(media_id.as_bytes());
    aad
}

fn hex_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 0x0f) as usize]));
    }
    out
}

pub fn atomic_write_file(target: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
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
            .create_folder(
                catalog.root_folder_id,
                secret_folder_name,
                1_700_000_000_100,
            )
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

    #[test]
    fn thumb_pack_encrypts_and_reads_back_in_ram() {
        let dir = std::env::temp_dir().join(format!("mv_thumb_test_{}", Uuid::new_v4()));
        let layout = VaultLayout::new(&dir);
        let mvk = MasterVaultKey::generate();
        let mut catalog = VaultCatalog::new(Uuid::new_v4(), 1_700_000_000_000);
        let media_id = Uuid::new_v4();
        let secret_thumb = b"SECRET_THUMBNAIL_PAYLOAD_WEBP_BYTES";

        let locator = layout
            .append_thumbnail(&mvk, &mut catalog, media_id, secret_thumb)
            .expect("append thumb");

        let pack_disk_bytes = fs::read(layout.thumb_pack_path(locator.pack_id)).expect("read pack");
        assert!(!pack_disk_bytes
            .windows(secret_thumb.len())
            .any(|w| w == secret_thumb));

        let plain = layout
            .read_thumbnail(&mvk, &catalog, media_id, locator)
            .expect("read thumb");
        assert_eq!(&*plain, secret_thumb);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn trash_shred_dhash_search_audit_and_doctor_work() {
        let dir = std::env::temp_dir().join(format!("mv_stage4_storage_{}", Uuid::new_v4()));
        let layout = VaultLayout::new(&dir);
        let mvk = MasterVaultKey::generate();
        let vault_id = Uuid::new_v4();
        let mut catalog = VaultCatalog::new(vault_id, 1_700_000_000_000);

        let m1 = Uuid::new_v4();
        let m2 = Uuid::new_v4();
        let folder = catalog.root_folder_id;
        let fek = FileEncryptionKey::generate();
        let wrapped = wrap_fek(&mvk, m1, &fek).unwrap().to_vec();

        fs::create_dir_all(layout.blob_path(m1).parent().unwrap()).unwrap();
        fs::write(layout.blob_path(m1), b"encrypted-blob-1").unwrap();
        fs::create_dir_all(layout.blob_path(m2).parent().unwrap()).unwrap();
        fs::write(layout.blob_path(m2), b"encrypted-blob-2").unwrap();

        catalog.media.insert(
            m1,
            MediaEntry {
                id: m1,
                folder_id: folder,
                linked_folder_ids: Vec::new(),
                original_name: "passport_scan.jpg".to_string(),
                mime_type: "image/jpeg".to_string(),
                kind: MediaKind::Photo,
                plaintext_size: 1024,
                dedup_blake3: [0x11; 32],
                phash: Some(0xFFFF_0000_0000_0000),
                width: None,
                height: None,
                exif_camera: Some("Pixel 9 Pro".to_string()),
                micro_thumb: None,
                wrapped_fek: wrapped.clone(),
                thumb: None,
                tags: vec!["documents".to_string()],
                note_markdown: Some("Confidential trip visa".to_string()),
                favorite: false,
                trashed_at_unix_ms: None,
                captured_at_unix_ms: Some(1_700_000_100_000),
                imported_at_unix_ms: 1_700_000_100_000,
            },
        );
        catalog.media.insert(
            m2,
            MediaEntry {
                id: m2,
                folder_id: folder,
                linked_folder_ids: Vec::new(),
                original_name: "passport_scan_2.jpg".to_string(),
                mime_type: "image/jpeg".to_string(),
                kind: MediaKind::Photo,
                plaintext_size: 1024,
                dedup_blake3: [0x22; 32],
                phash: Some(0xFFFF_0000_0000_0003),
                width: None,
                height: None,
                exif_camera: None,
                micro_thumb: None,
                wrapped_fek: wrapped,
                thumb: None,
                tags: vec![],
                note_markdown: None,
                favorite: false,
                trashed_at_unix_ms: None,
                captured_at_unix_ms: Some(1_700_000_200_000),
                imported_at_unix_ms: 1_700_000_200_000,
            },
        );
        catalog.dedup_index.insert(hex_32(&[0x11; 32]), m1);

        // Search and dHash clustering
        assert_eq!(catalog.search_media("visa").len(), 1);
        let groups = catalog.find_similar_by_dhash(4);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].media_ids.len(), 2);

        // Trash + expired purge shred
        catalog.move_to_trash(m1, 1_700_000_000_000).unwrap();
        assert_eq!(catalog.timeline_media().len(), 1);
        assert_eq!(catalog.list_trashed_media().len(), 1);
        let purged = catalog
            .purge_expired_trash(&layout, 30, 1_700_000_000_000 + 31 * 86_400_000)
            .unwrap();
        assert_eq!(purged, 1);
        assert!(!layout.blob_path(m1).exists());
        assert!(!catalog.dedup_index.contains_key(&hex_32(&[0x11; 32])));

        // Encrypted audit log hides text on disk
        layout
            .append_audit_event(
                &mvk,
                vault_id,
                AuditLogEntry {
                    timestamp_unix_ms: 1_700_000_500_000,
                    kind: AuditEventKind::TrashPurged,
                    detail: "SECRET_AUDIT_DETAIL".to_string(),
                },
            )
            .unwrap();
        let disk_audit = fs::read(layout.audit_log_path()).unwrap();
        assert!(!disk_audit
            .windows(b"SECRET_AUDIT_DETAIL".len())
            .any(|w| w == b"SECRET_AUDIT_DETAIL"));
        assert_eq!(layout.load_audit_events(&mvk, vault_id).unwrap().len(), 1);

        // Brute-force backoff schedule
        assert_eq!(compute_backoff_seconds(2), 0);
        assert_eq!(compute_backoff_seconds(3), 1);
        assert_eq!(compute_backoff_seconds(5), 4);
        assert_eq!(compute_backoff_seconds(20), 60);

        let doctor = layout.doctor_report(Some(&catalog));
        assert_eq!(doctor.media_count, 1);
        assert_eq!(doctor.missing_blobs_count, 0);

        let _ = fs::remove_dir_all(&dir);
    }
}
