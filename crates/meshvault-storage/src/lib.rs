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
                let wrapped: [u8; WRAPPED_FEK_LEN] = meta
                    .wrapped_fek
                    .as_slice()
                    .try_into()
                    .map_err(|_| StorageError::InvalidThumbPack("invalid wrapped FEK".into()))?;
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
}
