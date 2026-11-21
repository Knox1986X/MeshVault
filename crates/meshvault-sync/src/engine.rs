use std::collections::BTreeSet;
use std::fs;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshvault_crypto::{CryptoError, MasterVaultKey, TAG_LEN, XNONCE_LEN};
use meshvault_storage::{VaultCatalog, VaultLayout};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::SyncError;
use crate::transport::{RemoteSyncTransport, DROPBOX_APP_ROOT};
use crate::SyncState;

const MANIFEST_MAGIC: [u8; 4] = *b"MVSM";
const PAD_ENVELOPE_MAGIC: [u8; 4] = *b"MVPD";
const SYNC_MANIFEST_CONTEXT: &str = "MeshVault v1 Sync Manifest Key";
const CLOUD_PAD_CONTEXT: &str = "MeshVault v1 Cloud Pad Envelope";

/// Network and power conditions checked before running automatic sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceNetworkState {
    pub on_wifi: bool,
    pub is_metered: bool,
    pub is_charging: bool,
    pub battery_percent: u8,
}

impl Default for DeviceNetworkState {
    fn default() -> Self {
        Self {
            on_wifi: true,
            is_metered: false,
            is_charging: true,
            battery_percent: 100,
        }
    }
}

/// Smart synchronization policy (Wi-Fi only, charging, battery floor, cloud size padding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPolicy {
    pub wifi_only: bool,
    pub require_charging: bool,
    pub min_battery_percent: u8,
    pub size_padding_bucket_bytes: usize,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        Self {
            wifi_only: true,
            require_charging: false,
            min_battery_percent: 20,
            size_padding_bucket_bytes: 0,
        }
    }
}

/// Controls whether sync downloads all `.mvb` originals or only catalog + `.mvt` thumbnails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncDownloadMode {
    FullMirror,
    MetadataAndThumbsOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteBlobDescriptor {
    pub media_id: Uuid,
    pub ciphertext_blake3: [u8; 32],
    pub raw_ciphertext_len: u64,
    pub uploaded_len: u64,
}

/// Encrypted manifest stored per epoch at `/MeshVault/vaults/<vault_id>/manifest.json.enc`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSyncManifest {
    pub vault_id: Uuid,
    pub epoch: u64,
    pub origin_device_id: Uuid,
    pub catalog_revision: u64,
    pub catalog_hash: [u8; 32],
    pub blobs: Vec<RemoteBlobDescriptor>,
    pub thumb_pack_ids: Vec<Uuid>,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub state: SyncState,
    pub new_epoch: u64,
    pub uploaded_blobs: u64,
    pub downloaded_blobs: u64,
    pub downloaded_thumb_packs: u64,
    pub merged_conflict: bool,
    pub bytes_transferred: u64,
}

/// Zero-knowledge cloud & local-mirror synchronization engine.
pub struct SyncEngine {
    pub device_id: Uuid,
    pub last_synced_epoch: u64,
    pub last_synced_catalog_revision: u64,
}

impl SyncEngine {
    pub fn new(device_id: Uuid, last_synced_epoch: u64) -> Self {
        Self {
            device_id,
            last_synced_epoch,
            last_synced_catalog_revision: if last_synced_epoch == 0 { 1 } else { 0 },
        }
    }

    pub fn vault_prefix(vault_id: Uuid) -> String {
        format!("{DROPBOX_APP_ROOT}vaults/{}/", vault_id.simple())
    }

    fn remote_manifest_path(vault_id: Uuid) -> String {
        format!("{}manifest.mvsm", Self::vault_prefix(vault_id))
    }

    fn remote_header_path(vault_id: Uuid) -> String {
        format!("{}vault.header", Self::vault_prefix(vault_id))
    }

    fn remote_catalog_path(vault_id: Uuid) -> String {
        format!("{}catalog.mvc", Self::vault_prefix(vault_id))
    }

    fn remote_blob_path(vault_id: Uuid, media_id: Uuid) -> String {
        let hex = media_id.simple().to_string();
        format!(
            "{}blobs/{}/{hex}.mvb",
            Self::vault_prefix(vault_id),
            &hex[..2]
        )
    }

    fn remote_thumb_pack_path(vault_id: Uuid, pack_id: Uuid) -> String {
        format!(
            "{}thumbs/pack_{}.mvt",
            Self::vault_prefix(vault_id),
            pack_id.simple()
        )
    }

    /// Evaluates smart sync rules before touching the network.
    pub fn check_policy(policy: SyncPolicy, net: DeviceNetworkState) -> bool {
        if policy.wifi_only && (!net.on_wifi || net.is_metered) {
            return false;
        }
        if policy.require_charging && !net.is_charging {
            return false;
        }
        if net.battery_percent < policy.min_battery_percent {
            return false;
        }
        true
    }

    /// Runs bidirectional zero-knowledge sync against any `RemoteSyncTransport`.
    #[allow(clippy::too_many_arguments)]
    pub fn sync_vault(
        &mut self,
        layout: &VaultLayout,
        mvk: &MasterVaultKey,
        local_catalog: &mut VaultCatalog,
        transport: &dyn RemoteSyncTransport,
        policy: SyncPolicy,
        net: DeviceNetworkState,
        download_mode: SyncDownloadMode,
        now_unix_ms: u64,
    ) -> Result<SyncReport, SyncError> {
        if !Self::check_policy(policy, net) {
            return Ok(SyncReport {
                state: SyncState::PausedMetered,
                new_epoch: self.last_synced_epoch,
                uploaded_blobs: 0,
                downloaded_blobs: 0,
                downloaded_thumb_packs: 0,
                merged_conflict: false,
                bytes_transferred: 0,
            });
        }

        let vault_id = local_catalog.vault_id;
        let mut uploaded_blobs = 0u64;
        let mut downloaded_blobs = 0u64;
        let mut downloaded_thumb_packs = 0u64;
        let mut bytes_transferred = 0u64;
        let mut merged_conflict = false;

        let remote_manifest = match transport.get_object(&Self::remote_manifest_path(vault_id)) {
            Ok(bytes) => Some(open_manifest(mvk, vault_id, &bytes)?),
            Err(SyncError::RemoteNotFound(_)) => None,
            Err(e) => return Err(e),
        };

        let mut next_epoch = 1u64;

        if let Some(remote) = &remote_manifest {
            let remote_catalog_bytes =
                transport.get_object(&Self::remote_catalog_path(vault_id))?;
            bytes_transferred += remote_catalog_bytes.len() as u64;
            let remote_catalog = VaultCatalog::open(mvk, &remote_catalog_bytes)?;

            let remote_changed = remote.epoch > self.last_synced_epoch;
            let local_changed = if self.last_synced_epoch == 0 {
                (!local_catalog.media.is_empty() || local_catalog.catalog_revision > 1)
                    && remote.origin_device_id != self.device_id
            } else {
                local_catalog.catalog_revision > self.last_synced_catalog_revision
                    && remote.origin_device_id != self.device_id
            };

            if remote_changed && local_changed {
                merge_catalogs_lww(local_catalog, &remote_catalog, remote.origin_device_id);
                merged_conflict = true;
            } else if remote_changed && !local_changed {
                merge_catalogs_lww(local_catalog, &remote_catalog, remote.origin_device_id);
            }
            next_epoch = remote.epoch.saturating_add(1);

            // Download missing thumbnail packs first (used by both FullMirror & On-Demand modes).
            for pack_id in &remote.thumb_pack_ids {
                let local_pack = layout.thumb_pack_path(*pack_id);
                if !local_pack.exists() {
                    let remote_pack =
                        transport.get_object(&Self::remote_thumb_pack_path(vault_id, *pack_id))?;
                    bytes_transferred += remote_pack.len() as u64;
                    meshvault_storage::atomic_write_file(&local_pack, &remote_pack)?;
                    downloaded_thumb_packs += 1;
                }
            }

            // Download missing `.mvb` originals if FullMirror is requested.
            if download_mode == SyncDownloadMode::FullMirror {
                for desc in &remote.blobs {
                    if local_catalog.media.contains_key(&desc.media_id) {
                        let local_blob = layout.blob_path(desc.media_id);
                        if !local_blob.exists() {
                            let payload = transport
                                .get_object(&Self::remote_blob_path(vault_id, desc.media_id))?;
                            bytes_transferred += payload.len() as u64;
                            let raw_mvb = decode_cloud_envelope(mvk, desc.media_id, &payload)?;
                            meshvault_storage::atomic_write_file(&local_blob, &raw_mvb)?;
                            downloaded_blobs += 1;
                        }
                    }
                }
            }
        }

        // Persist updated local catalog.
        layout.save_catalog(mvk, local_catalog)?;

        // Upload header if missing or updated.
        if let Ok(header_bytes) = fs::read(layout.primary_header_path()) {
            transport.put_object(&Self::remote_header_path(vault_id), &header_bytes)?;
            bytes_transferred += header_bytes.len() as u64;
        }

        // Upload missing thumbnail packs.
        for pack_id in local_catalog.thumb_packs.keys() {
            let local_pack = layout.thumb_pack_path(*pack_id);
            if local_pack.exists() {
                let remote_path = Self::remote_thumb_pack_path(vault_id, *pack_id);
                if transport.get_object(&remote_path).is_err() {
                    let pack_bytes = fs::read(&local_pack)?;
                    transport.put_object(&remote_path, &pack_bytes)?;
                    bytes_transferred += pack_bytes.len() as u64;
                }
            }
        }

        // Upload any local `.mvb` blobs missing from remote, with optional size padding.
        let mut remote_blob_ids: BTreeSet<Uuid> = remote_manifest
            .as_ref()
            .map(|m| m.blobs.iter().map(|b| b.media_id).collect())
            .unwrap_or_default();

        let mut descriptors = remote_manifest.map(|m| m.blobs).unwrap_or_default();

        for media_id in local_catalog.media.keys() {
            let local_blob = layout.blob_path(*media_id);
            if !local_blob.exists() {
                continue;
            }
            if !remote_blob_ids.contains(media_id) {
                let raw_mvb = fs::read(&local_blob)?;
                let raw_hash = *blake3::hash(&raw_mvb).as_bytes();
                let upload_payload = if policy.size_padding_bucket_bytes > 0 {
                    encode_padded_cloud_envelope(
                        mvk,
                        *media_id,
                        &raw_mvb,
                        policy.size_padding_bucket_bytes,
                    )?
                } else {
                    raw_mvb.clone()
                };
                let remote_path = Self::remote_blob_path(vault_id, *media_id);
                transport.upload_chunked_resume(&remote_path, &upload_payload, 0, 256 * 1024)?;
                bytes_transferred += upload_payload.len() as u64;
                uploaded_blobs += 1;
                remote_blob_ids.insert(*media_id);
                descriptors.push(RemoteBlobDescriptor {
                    media_id: *media_id,
                    ciphertext_blake3: raw_hash,
                    raw_ciphertext_len: raw_mvb.len() as u64,
                    uploaded_len: upload_payload.len() as u64,
                });
            }
        }

        // Remove shredded blobs from manifest that no longer exist in merged catalog.
        descriptors.retain(|d| local_catalog.media.contains_key(&d.media_id));

        let sealed_catalog = fs::read(layout.catalog_path())?;
        let catalog_hash = *blake3::hash(&sealed_catalog).as_bytes();
        transport.put_object(&Self::remote_catalog_path(vault_id), &sealed_catalog)?;
        bytes_transferred += sealed_catalog.len() as u64;

        let new_manifest = EncryptedSyncManifest {
            vault_id,
            epoch: next_epoch,
            origin_device_id: self.device_id,
            catalog_revision: local_catalog.catalog_revision,
            catalog_hash,
            blobs: descriptors,
            thumb_pack_ids: local_catalog.thumb_packs.keys().copied().collect(),
            updated_at_unix_ms: now_unix_ms,
        };
        let sealed_manifest = seal_manifest(mvk, &new_manifest)?;
        transport.put_object(&Self::remote_manifest_path(vault_id), &sealed_manifest)?;
        bytes_transferred += sealed_manifest.len() as u64;

        self.last_synced_epoch = next_epoch;
        self.last_synced_catalog_revision = local_catalog.catalog_revision;

        Ok(SyncReport {
            state: if merged_conflict {
                SyncState::ConflictResolved
            } else {
                SyncState::Synced
            },
            new_epoch: next_epoch,
            uploaded_blobs,
            downloaded_blobs,
            downloaded_thumb_packs,
            merged_conflict,
            bytes_transferred,
        })
    }

    /// Downloads a single encrypted `.mvb` original on demand when Selective Sync is enabled.
    pub fn fetch_blob_on_demand(
        &self,
        layout: &VaultLayout,
        mvk: &MasterVaultKey,
        vault_id: Uuid,
        media_id: Uuid,
        transport: &dyn RemoteSyncTransport,
    ) -> Result<u64, SyncError> {
        let local_blob = layout.blob_path(media_id);
        if local_blob.exists() {
            return Ok(fs::metadata(local_blob)?.len());
        }
        let payload = transport.get_object(&Self::remote_blob_path(vault_id, media_id))?;
        let raw_mvb = decode_cloud_envelope(mvk, media_id, &payload)?;
        let len = raw_mvb.len() as u64;
        meshvault_storage::atomic_write_file(&local_blob, &raw_mvb)?;
        Ok(len)
    }
}

/// Non-destructive Last-Writer-Wins catalog merge preserving folders and media from both peers.
pub fn merge_catalogs_lww(local: &mut VaultCatalog, remote: &VaultCatalog, remote_device_id: Uuid) {
    let suffix = format!("conflict-{}", &remote_device_id.simple().to_string()[..6]);

    for (folder_id, remote_folder) in &remote.folders {
        if let Some(local_folder) = local.folders.get_mut(folder_id) {
            if local_folder.name != remote_folder.name
                && remote_folder.created_at_unix_ms > local_folder.created_at_unix_ms
            {
                local_folder.name = remote_folder.name.clone();
            }
            local_folder.pinned |= remote_folder.pinned;
            local_folder.blur_shield |= remote_folder.blur_shield;
        } else {
            let mut copy = remote_folder.clone();
            let same_name_sibling = local
                .folders
                .values()
                .any(|f| f.parent_id == copy.parent_id && f.name.eq_ignore_ascii_case(&copy.name));
            if same_name_sibling {
                copy.name = format!("{} ({suffix})", copy.name);
            }
            local.folders.insert(*folder_id, copy);
        }
    }

    for (media_id, remote_entry) in &remote.media {
        if let Some(local_entry) = local.media.get_mut(media_id) {
            if remote_entry.imported_at_unix_ms > local_entry.imported_at_unix_ms {
                *local_entry = remote_entry.clone();
            }
        } else {
            local.insert_media(remote_entry.clone());
        }
    }

    for (pack_id, pack_meta) in &remote.thumb_packs {
        local
            .thumb_packs
            .entry(*pack_id)
            .or_insert_with(|| pack_meta.clone());
    }

    local.catalog_revision = local
        .catalog_revision
        .max(remote.catalog_revision)
        .saturating_add(1);
}

fn seal_manifest(
    mvk: &MasterVaultKey,
    manifest: &EncryptedSyncManifest,
) -> Result<Vec<u8>, SyncError> {
    let key = mvk.derive_subkey(SYNC_MANIFEST_CONTEXT, b"manifest-v1");
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| SyncError::InvalidManifest("invalid key length".to_string()))?;
    let plain = Zeroizing::new(serde_json::to_vec(manifest)?);
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut aad = Vec::with_capacity(28);
    aad.extend_from_slice(&MANIFEST_MAGIC);
    aad.extend_from_slice(manifest.vault_id.as_bytes());
    aad.extend_from_slice(&manifest.epoch.to_le_bytes());

    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plain.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let mut out = Vec::with_capacity(4 + 16 + 8 + XNONCE_LEN + ct.len());
    out.extend_from_slice(&MANIFEST_MAGIC);
    out.extend_from_slice(manifest.vault_id.as_bytes());
    out.extend_from_slice(&manifest.epoch.to_le_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_manifest(
    mvk: &MasterVaultKey,
    expected_vault_id: Uuid,
    sealed: &[u8],
) -> Result<EncryptedSyncManifest, SyncError> {
    if sealed.len() < 4 + 16 + 8 + XNONCE_LEN + TAG_LEN || sealed[0..4] != MANIFEST_MAGIC {
        return Err(SyncError::InvalidManifest(
            "invalid manifest magic or truncated".to_string(),
        ));
    }
    if sealed[4..20] != *expected_vault_id.as_bytes() {
        return Err(SyncError::InvalidManifest(
            "manifest vault_id mismatch".to_string(),
        ));
    }
    let epoch = u64::from_le_bytes([
        sealed[20], sealed[21], sealed[22], sealed[23], sealed[24], sealed[25], sealed[26],
        sealed[27],
    ]);
    let nonce = XNonce::from_slice(&sealed[28..28 + XNONCE_LEN]);
    let ct = &sealed[28 + XNONCE_LEN..];
    let key = mvk.derive_subkey(SYNC_MANIFEST_CONTEXT, b"manifest-v1");
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| SyncError::InvalidManifest("invalid key length".to_string()))?;
    let mut aad = Vec::with_capacity(28);
    aad.extend_from_slice(&MANIFEST_MAGIC);
    aad.extend_from_slice(expected_vault_id.as_bytes());
    aad.extend_from_slice(&epoch.to_le_bytes());

    let plain = Zeroizing::new(
        cipher
            .decrypt(nonce, Payload { msg: ct, aad: &aad })
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    Ok(serde_json::from_slice(&plain)?)
}

/// Wraps a `.mvb` ciphertext in an authenticated fixed-bucket envelope (`FLAG_SIZE_PADDING`).
pub fn encode_padded_cloud_envelope(
    mvk: &MasterVaultKey,
    media_id: Uuid,
    raw_mvb: &[u8],
    bucket_bytes: usize,
) -> Result<Vec<u8>, SyncError> {
    let bucket = bucket_bytes.max(1024);
    let overhead = 4 + 16 + XNONCE_LEN + 8 + TAG_LEN;
    let min_total = overhead + raw_mvb.len();
    let target_total = min_total.div_ceil(bucket) * bucket;
    let pad_len = target_total - min_total;

    let mut plain = Zeroizing::new(Vec::with_capacity(8 + raw_mvb.len() + pad_len));
    plain.extend_from_slice(&(raw_mvb.len() as u64).to_le_bytes());
    plain.extend_from_slice(raw_mvb);
    if pad_len > 0 {
        let start = plain.len();
        plain.resize(start + pad_len, 0u8);
        OsRng.fill_bytes(&mut plain[start..]);
    }

    let key = mvk.derive_subkey(CLOUD_PAD_CONTEXT, media_id.as_bytes());
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| SyncError::InvalidManifest("invalid pad key".to_string()))?;
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut aad = Vec::with_capacity(20);
    aad.extend_from_slice(&PAD_ENVELOPE_MAGIC);
    aad.extend_from_slice(media_id.as_bytes());

    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plain.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let mut out = Vec::with_capacity(4 + 16 + XNONCE_LEN + ct.len());
    out.extend_from_slice(&PAD_ENVELOPE_MAGIC);
    out.extend_from_slice(media_id.as_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwraps either a `MVPD` padded cloud envelope or a raw `MVB1` blob.
pub fn decode_cloud_envelope(
    mvk: &MasterVaultKey,
    media_id: Uuid,
    payload: &[u8],
) -> Result<Vec<u8>, SyncError> {
    if payload.len() >= 4 && payload[0..4] == PAD_ENVELOPE_MAGIC {
        if payload.len() < 4 + 16 + XNONCE_LEN + 8 + TAG_LEN
            || payload[4..20] != *media_id.as_bytes()
        {
            return Err(SyncError::InvalidManifest(
                "invalid padded cloud envelope".to_string(),
            ));
        }
        let key = mvk.derive_subkey(CLOUD_PAD_CONTEXT, media_id.as_bytes());
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
            .map_err(|_| SyncError::InvalidManifest("invalid pad key".to_string()))?;
        let nonce = XNonce::from_slice(&payload[20..20 + XNONCE_LEN]);
        let ct = &payload[20 + XNONCE_LEN..];
        let mut aad = Vec::with_capacity(20);
        aad.extend_from_slice(&PAD_ENVELOPE_MAGIC);
        aad.extend_from_slice(media_id.as_bytes());
        let plain = Zeroizing::new(
            cipher
                .decrypt(nonce, Payload { msg: ct, aad: &aad })
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        );
        let real_len = u64::from_le_bytes([
            plain[0], plain[1], plain[2], plain[3], plain[4], plain[5], plain[6], plain[7],
        ]) as usize;
        if 8 + real_len > plain.len() {
            return Err(SyncError::InvalidManifest(
                "padded envelope length out of bounds".to_string(),
            ));
        }
        return Ok(plain[8..8 + real_len].to_vec());
    }
    Ok(payload.to_vec())
}
