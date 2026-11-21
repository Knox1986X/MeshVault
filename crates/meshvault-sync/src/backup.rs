use std::fs;
use std::path::Path;

use meshvault_crypto::MasterVaultKey;
use meshvault_storage::{atomic_write_file, ScrubReport, VaultCatalog, VaultLayout};

use crate::error::SyncError;

/// Summary of an offline encrypted backup export + immediate Poly1305 scrub verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub copied_blobs: u64,
    pub copied_thumb_packs: u64,
    pub scrub: ScrubReport,
}

/// Exports a full standalone encrypted vault backup to USB OTG / Btrfs / LUKS
/// and runs `scrub_vault` on the destination directory to guarantee zero corruption.
pub fn export_verified_backup(
    source_layout: &VaultLayout,
    mvk: &MasterVaultKey,
    catalog: &VaultCatalog,
    dest_dir: &Path,
) -> Result<BackupReport, SyncError> {
    let dest_layout = VaultLayout::new(dest_dir);
    dest_layout.ensure_directories()?;

    let primary_hdr = fs::read(source_layout.primary_header_path())?;
    atomic_write_file(&dest_layout.primary_header_path(), &primary_hdr)?;
    if let Ok(bak_hdr) = fs::read(source_layout.backup_header_path()) {
        atomic_write_file(&dest_layout.backup_header_path(), &bak_hdr)?;
    } else {
        atomic_write_file(&dest_layout.backup_header_path(), &primary_hdr)?;
    }

    let catalog_bytes = fs::read(source_layout.catalog_path())?;
    atomic_write_file(&dest_layout.catalog_path(), &catalog_bytes)?;

    let mut copied_blobs = 0u64;
    for media_id in catalog.media.keys() {
        let src_blob = source_layout.blob_path(*media_id);
        if src_blob.exists() {
            let data = fs::read(&src_blob)?;
            atomic_write_file(&dest_layout.blob_path(*media_id), &data)?;
            copied_blobs += 1;
        }
    }

    let mut copied_thumb_packs = 0u64;
    for pack_id in catalog.thumb_packs.keys() {
        let src_pack = source_layout.thumb_pack_path(*pack_id);
        if src_pack.exists() {
            let data = fs::read(&src_pack)?;
            atomic_write_file(&dest_layout.thumb_pack_path(*pack_id), &data)?;
            copied_thumb_packs += 1;
        }
    }

    let dest_catalog = dest_layout.load_catalog(mvk)?;
    let scrub = dest_layout.scrub_vault(mvk, &dest_catalog)?;
    if !scrub.corrupted_blobs.is_empty() || !scrub.missing_blobs.is_empty() {
        return Err(SyncError::InvalidManifest(
            "backup verification scrub detected missing or corrupted blobs".to_string(),
        ));
    }

    Ok(BackupReport {
        copied_blobs,
        copied_thumb_packs,
        scrub,
    })
}
