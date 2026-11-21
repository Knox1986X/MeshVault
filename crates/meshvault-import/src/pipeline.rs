use std::collections::BTreeSet;
use std::fs;
use std::io::Cursor;
use std::path::Path;

use meshvault_crypto::{
    encrypt_stream, wrap_fek, ChunkedBlobReader, FileEncryptionKey, MasterVaultKey,
    DEFAULT_CHUNK_SIZE,
};
use meshvault_storage::{MediaEntry, VaultCatalog, VaultLayout};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::exif::extract_metadata_and_thumbnails;
use crate::scanner::{scan_directory_tree, ScanOptions};
use crate::wal::{ImportWal, WalItem};
use crate::{DedupPolicy, ImportState};

/// Configuration for a transactional recursive folder import job.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    pub dedup_policy: DedupPolicy,
    pub chunk_size: usize,
    pub generate_thumbnails: bool,
    pub checkpoint_every: usize,
    pub scan_options: ScanOptions,
    pub selected_relative_folders: Option<BTreeSet<String>>,
    /// Test hook simulating abrupt process termination after N newly processed items.
    pub max_items_before_simulated_crash: Option<usize>,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            dedup_policy: DedupPolicy::SkipDuplicate,
            chunk_size: DEFAULT_CHUNK_SIZE,
            generate_thumbnails: true,
            checkpoint_every: 64,
            scan_options: ScanOptions::default(),
            selected_relative_folders: None,
            max_items_before_simulated_crash: None,
        }
    }
}

/// Quarantine entry recorded when a source file is unreadable, empty, or corrupted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinedItem {
    pub source_path: String,
    pub reason: String,
}

/// Final summary report emitted after an import or resumed import finishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    pub job_id: Uuid,
    pub final_state: ImportState,
    pub imported_files: usize,
    pub skipped_duplicates: usize,
    pub linked_duplicates: usize,
    pub created_folders: usize,
    pub quarantined_files: Vec<QuarantinedItem>,
    pub bytes_encrypted: u64,
    pub resumed_from_wal: bool,
}

/// Transactional recursive folder import pipeline with WAL crash recovery.
pub struct ImportPipeline;

/// Outcome of importing a single in-memory stream item (for example from Android SAF).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleImportResult {
    pub media_id: Uuid,
    pub target_folder_id: Uuid,
    pub deduplicated_skip: bool,
    pub deduplicated_link: bool,
    pub bytes_encrypted: u64,
}

impl ImportPipeline {
    /// Imports a single media stream directly from RAM (used by Android SAF and Photo Picker)
    /// without ever writing plaintext bytes to temporary disk files.
    #[allow(clippy::too_many_arguments)]
    pub fn import_bytes_item(
        layout: &VaultLayout,
        mvk: &MasterVaultKey,
        catalog: &mut VaultCatalog,
        target_parent_id: Uuid,
        relative_folder_segments: &[String],
        file_name: &str,
        plain_bytes: &[u8],
        dedup_policy: DedupPolicy,
        captured_at_override_ms: Option<u64>,
        now_unix_ms: u64,
    ) -> Result<SingleImportResult, ImportError> {
        if plain_bytes.is_empty() {
            return Err(ImportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "zero-length source file quarantined",
            )));
        }

        let seg_refs: Vec<&str> = relative_folder_segments
            .iter()
            .map(String::as_str)
            .collect();
        let target_folder_id =
            catalog.ensure_folder_path(target_parent_id, &seg_refs, now_unix_ms)?;

        let dedup_hash = mvk.keyed_dedup_hash(plain_bytes);
        if let Some(existing_id) = catalog.find_by_dedup_hash(&dedup_hash) {
            match dedup_policy {
                DedupPolicy::SkipDuplicate => {
                    return Ok(SingleImportResult {
                        media_id: existing_id,
                        target_folder_id,
                        deduplicated_skip: true,
                        deduplicated_link: false,
                        bytes_encrypted: 0,
                    });
                }
                DedupPolicy::LinkIntoTargetFolder => {
                    if let Some(existing) = catalog.media.get_mut(&existing_id) {
                        if existing.folder_id != target_folder_id
                            && !existing.linked_folder_ids.contains(&target_folder_id)
                        {
                            existing.linked_folder_ids.push(target_folder_id);
                            catalog.catalog_revision = catalog.catalog_revision.saturating_add(1);
                        }
                    }
                    return Ok(SingleImportResult {
                        media_id: existing_id,
                        target_folder_id,
                        deduplicated_skip: false,
                        deduplicated_link: true,
                        bytes_encrypted: 0,
                    });
                }
                DedupPolicy::KeepIndependentCopy => {}
            }
        }

        let item_id = Uuid::new_v4();
        let fek = FileEncryptionKey::generate();
        let part_path = layout.blob_part_path(item_id);
        if let Some(parent) = part_path.parent() {
            fs::create_dir_all(parent)?;
        }

        {
            let mut part_file = fs::File::create(&part_path)?;
            encrypt_stream(
                &mut Cursor::new(plain_bytes),
                &mut part_file,
                &fek,
                item_id,
                DEFAULT_CHUNK_SIZE,
            )?;
            part_file.sync_all()?;
        }

        let verify_file = fs::File::open(&part_path)?;
        let mut blob_reader = ChunkedBlobReader::open(verify_file)?;
        let verified_plain = blob_reader.verify_all_chunks(&fek)?;
        if verified_plain != plain_bytes.len() as u64 {
            let _ = fs::remove_file(&part_path);
            return Err(ImportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "post-encryption verification mismatch",
            )));
        }

        fs::rename(&part_path, layout.blob_path(item_id))?;

        let meta = extract_metadata_and_thumbnails(Path::new(file_name), plain_bytes, true);
        let thumb_locator = match meta.pack_thumb {
            Some(ref thumb_bytes) => {
                Some(layout.append_thumbnail(mvk, catalog, item_id, thumb_bytes)?)
            }
            None => None,
        };

        let wrapped_fek = wrap_fek(mvk, item_id, &fek)?.to_vec();
        let entry = MediaEntry {
            id: item_id,
            folder_id: target_folder_id,
            linked_folder_ids: Vec::new(),
            original_name: file_name.to_string(),
            mime_type: meta.mime_type,
            kind: meta.kind,
            plaintext_size: plain_bytes.len() as u64,
            dedup_blake3: dedup_hash,
            phash: meta.phash,
            width: meta.width,
            height: meta.height,
            exif_camera: meta.exif_camera,
            micro_thumb: meta.micro_thumb,
            wrapped_fek,
            thumb: thumb_locator,
            tags: Vec::new(),
            favorite: false,
            trashed_at_unix_ms: None,
            captured_at_unix_ms: meta.captured_at_unix_ms.or(captured_at_override_ms),
            imported_at_unix_ms: now_unix_ms,
        };

        catalog.insert_media(entry);
        layout.save_catalog(mvk, catalog)?;

        Ok(SingleImportResult {
            media_id: item_id,
            target_folder_id,
            deduplicated_skip: false,
            deduplicated_link: false,
            bytes_encrypted: plain_bytes.len() as u64,
        })
    }

    /// Scans `source_dir`, initializes an encrypted WAL, and executes the import into `catalog`.
    pub fn run_directory_import(
        layout: &VaultLayout,
        mvk: &MasterVaultKey,
        catalog: &mut VaultCatalog,
        source_dir: &Path,
        target_parent_id: Uuid,
        options: &ImportOptions,
        now_unix_ms: u64,
    ) -> Result<ImportReport, ImportError> {
        let preview = scan_directory_tree(source_dir, &options.scan_options)?;
        let mut wal_items = Vec::with_capacity(preview.items.len());

        for item in preview.items {
            if let Some(selected) = &options.selected_relative_folders {
                let rel_folder = item.relative_folder_segments.join("/");
                if !selected.contains(&rel_folder) {
                    continue;
                }
            }
            wal_items.push(WalItem {
                item_id: Uuid::new_v4(),
                relative_folder_segments: item.relative_folder_segments,
                file_name: item.file_name,
                source_path: item.source_path,
                state: ImportState::PreviewReady,
                verified_chunks: 0,
                total_chunks: 0,
                quarantine_reason: None,
            });
        }

        let mut wal = ImportWal {
            job_id: Uuid::new_v4(),
            target_parent_id,
            dedup_policy: options.dedup_policy,
            chunk_size: options.chunk_size,
            generate_thumbnails: options.generate_thumbnails,
            created_at_unix_ms: now_unix_ms,
            items: wal_items,
        };

        wal.save(layout, mvk)?;
        Self::execute_wal(layout, mvk, catalog, &mut wal, options, now_unix_ms, false)
    }

    /// Resumes an interrupted import from `wal/import.wal` after an abrupt process kill.
    pub fn resume_from_wal(
        layout: &VaultLayout,
        mvk: &MasterVaultKey,
        catalog: &mut VaultCatalog,
        max_items_before_simulated_crash: Option<usize>,
        now_unix_ms: u64,
    ) -> Result<ImportReport, ImportError> {
        let Some(mut wal) = ImportWal::load(layout, mvk)? else {
            return Err(ImportError::NoActiveWal);
        };

        let options = ImportOptions {
            dedup_policy: wal.dedup_policy,
            chunk_size: wal.chunk_size,
            generate_thumbnails: wal.generate_thumbnails,
            checkpoint_every: 64,
            scan_options: ScanOptions::default(),
            selected_relative_folders: None,
            max_items_before_simulated_crash,
        };

        Self::execute_wal(layout, mvk, catalog, &mut wal, &options, now_unix_ms, true)
    }

    fn execute_wal(
        layout: &VaultLayout,
        mvk: &MasterVaultKey,
        catalog: &mut VaultCatalog,
        wal: &mut ImportWal,
        options: &ImportOptions,
        now_unix_ms: u64,
        resumed_from_wal: bool,
    ) -> Result<ImportReport, ImportError> {
        cleanup_dangling_part_files(&layout.blobs_dir())?;

        let initial_folder_count = catalog.folders.len();
        let mut imported_files = 0usize;
        let mut skipped_duplicates = 0usize;
        let mut linked_duplicates = 0usize;
        let mut bytes_encrypted = 0u64;
        let mut quarantined_files = Vec::new();
        let mut newly_processed = 0usize;

        let checkpoint_every = options.checkpoint_every.max(1);
        let item_count = wal.items.len();

        for idx in 0..item_count {
            let current_state = wal.items[idx].state;
            if matches!(
                current_state,
                ImportState::CatalogCommitted | ImportState::Completed
            ) {
                continue;
            }
            if current_state == ImportState::Quarantined {
                quarantined_files.push(QuarantinedItem {
                    source_path: wal.items[idx].source_path.to_string_lossy().to_string(),
                    reason: wal.items[idx]
                        .quarantine_reason
                        .clone()
                        .unwrap_or_else(|| "quarantined".to_string()),
                });
                continue;
            }

            if let Some(limit) = options.max_items_before_simulated_crash {
                if newly_processed >= limit {
                    layout.save_catalog(mvk, catalog)?;
                    wal.save(layout, mvk)?;
                    return Err(ImportError::SimulatedCrash {
                        processed: newly_processed,
                    });
                }
            }

            let item_id = wal.items[idx].item_id;
            let source_path = wal.items[idx].source_path.clone();
            let file_name = wal.items[idx].file_name.clone();
            let rel_segments = wal.items[idx].relative_folder_segments.clone();

            wal.items[idx].state = ImportState::ImportingChunks;

            let plain_bytes = match fs::read(&source_path) {
                Ok(bytes) => Zeroizing::new(bytes),
                Err(err) => {
                    let reason = format!("read failed: {err}");
                    wal.items[idx].state = ImportState::Quarantined;
                    wal.items[idx].quarantine_reason = Some(reason.clone());
                    quarantined_files.push(QuarantinedItem {
                        source_path: source_path.to_string_lossy().to_string(),
                        reason,
                    });
                    newly_processed += 1;
                    continue;
                }
            };

            if plain_bytes.is_empty() {
                let reason = "zero-length source file".to_string();
                wal.items[idx].state = ImportState::Quarantined;
                wal.items[idx].quarantine_reason = Some(reason.clone());
                quarantined_files.push(QuarantinedItem {
                    source_path: source_path.to_string_lossy().to_string(),
                    reason,
                });
                newly_processed += 1;
                continue;
            }

            let seg_refs: Vec<&str> = rel_segments.iter().map(String::as_str).collect();
            let target_folder_id =
                catalog.ensure_folder_path(wal.target_parent_id, &seg_refs, now_unix_ms)?;

            let dedup_hash = mvk.keyed_dedup_hash(&plain_bytes);
            if let Some(existing_id) = catalog.find_by_dedup_hash(&dedup_hash) {
                match wal.dedup_policy {
                    DedupPolicy::SkipDuplicate => {
                        wal.items[idx].state = ImportState::CatalogCommitted;
                        skipped_duplicates += 1;
                        newly_processed += 1;
                        continue;
                    }
                    DedupPolicy::LinkIntoTargetFolder => {
                        if let Some(existing) = catalog.media.get_mut(&existing_id) {
                            if existing.folder_id != target_folder_id
                                && !existing.linked_folder_ids.contains(&target_folder_id)
                            {
                                existing.linked_folder_ids.push(target_folder_id);
                                catalog.catalog_revision =
                                    catalog.catalog_revision.saturating_add(1);
                            }
                        }
                        wal.items[idx].state = ImportState::CatalogCommitted;
                        linked_duplicates += 1;
                        newly_processed += 1;
                        continue;
                    }
                    DedupPolicy::KeepIndependentCopy => {}
                }
            }

            let fek = FileEncryptionKey::generate();
            let part_path = layout.blob_part_path(item_id);
            if let Some(parent) = part_path.parent() {
                fs::create_dir_all(parent)?;
            }

            {
                let mut part_file = fs::File::create(&part_path)?;
                encrypt_stream(
                    &mut Cursor::new(&*plain_bytes),
                    &mut part_file,
                    &fek,
                    item_id,
                    wal.chunk_size,
                )?;
                part_file.sync_all()?;
            }

            // Transition: ImportingChunks -> VerifyingTags
            wal.items[idx].state = ImportState::VerifyingTags;
            let verify_file = fs::File::open(&part_path)?;
            let mut blob_reader = ChunkedBlobReader::open(verify_file)?;
            let total_chunks = blob_reader.total_chunks();
            let verified_plain = blob_reader.verify_all_chunks(&fek)?;
            if verified_plain != plain_bytes.len() as u64 {
                let _ = fs::remove_file(&part_path);
                let reason = "verified byte count mismatch".to_string();
                wal.items[idx].state = ImportState::Quarantined;
                wal.items[idx].quarantine_reason = Some(reason.clone());
                quarantined_files.push(QuarantinedItem {
                    source_path: source_path.to_string_lossy().to_string(),
                    reason,
                });
                newly_processed += 1;
                continue;
            }

            let final_blob_path = layout.blob_path(item_id);
            fs::rename(&part_path, &final_blob_path)?;

            let meta = extract_metadata_and_thumbnails(
                &source_path,
                &plain_bytes,
                wal.generate_thumbnails,
            );
            let thumb_locator = match meta.pack_thumb {
                Some(ref thumb_bytes) => {
                    Some(layout.append_thumbnail(mvk, catalog, item_id, thumb_bytes)?)
                }
                None => None,
            };

            let wrapped_fek = wrap_fek(mvk, item_id, &fek)?.to_vec();
            let entry = MediaEntry {
                id: item_id,
                folder_id: target_folder_id,
                linked_folder_ids: Vec::new(),
                original_name: file_name,
                mime_type: meta.mime_type,
                kind: meta.kind,
                plaintext_size: plain_bytes.len() as u64,
                dedup_blake3: dedup_hash,
                phash: meta.phash,
                width: meta.width,
                height: meta.height,
                exif_camera: meta.exif_camera,
                micro_thumb: meta.micro_thumb,
                wrapped_fek,
                thumb: thumb_locator,
                tags: Vec::new(),
                favorite: false,
                trashed_at_unix_ms: None,
                captured_at_unix_ms: meta.captured_at_unix_ms,
                imported_at_unix_ms: now_unix_ms,
            };

            catalog.insert_media(entry);
            wal.items[idx].state = ImportState::CatalogCommitted;
            wal.items[idx].verified_chunks = total_chunks;
            wal.items[idx].total_chunks = total_chunks;

            imported_files += 1;
            bytes_encrypted = bytes_encrypted.saturating_add(plain_bytes.len() as u64);
            newly_processed += 1;

            if newly_processed % checkpoint_every == 0 {
                layout.save_catalog(mvk, catalog)?;
                wal.save(layout, mvk)?;
            }
        }

        layout.save_catalog(mvk, catalog)?;

        for item in &mut wal.items {
            if item.state == ImportState::CatalogCommitted {
                item.state = ImportState::Completed;
            }
        }
        ImportWal::clear(layout)?;

        Ok(ImportReport {
            job_id: wal.job_id,
            final_state: ImportState::Completed,
            imported_files,
            skipped_duplicates,
            linked_duplicates,
            created_folders: catalog.folders.len().saturating_sub(initial_folder_count),
            quarantined_files,
            bytes_encrypted,
            resumed_from_wal,
        })
    }
}

/// Generates a nested synthetic folder tree with unique synthetic media files (Requirement 80).
pub fn generate_synthetic_tree(
    root_dir: &Path,
    branch_folders: usize,
    subfolders_per_branch: usize,
    files_per_leaf: usize,
) -> Result<usize, ImportError> {
    fs::create_dir_all(root_dir)?;
    let mut created = 0usize;

    for b in 0..branch_folders {
        for s in 0..subfolders_per_branch {
            let leaf = root_dir
                .join(format!("trip_{b:03}"))
                .join(format!("day_{s:02}"))
                .join("camera_roll");
            fs::create_dir_all(&leaf)?;

            for f in 0..files_per_leaf {
                let file_path = leaf.join(format!("IMG_{b:03}_{s:02}_{f:03}.jpg"));
                let payload = format!("MESHVAULT_SYNTHETIC_MEDIA_{b}_{s}_{f}");
                fs::write(&file_path, payload.as_bytes())?;
                created += 1;
            }
        }
    }

    Ok(created)
}

fn cleanup_dangling_part_files(blobs_dir: &Path) -> Result<(), ImportError> {
    if !blobs_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(blobs_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            cleanup_dangling_part_files(&path)?;
        } else if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if name.ends_with(".mvb.part") {
                let _ = fs::remove_file(path);
            }
        }
    }
    Ok(())
}
