pub mod error;
pub mod exif;
pub mod pipeline;
pub mod scanner;
pub mod wal;

pub use error::ImportError;
pub use exif::{
    classify_by_extension, compute_dhash_64, extract_metadata_and_thumbnails,
    parse_exif_datetime_unix_ms, parse_jpeg_exif, ExtractedMediaMeta, ParsedExif,
};
pub use pipeline::{
    generate_synthetic_tree, ImportOptions, ImportPipeline, ImportReport, QuarantinedItem,
    SingleImportResult,
};
pub use scanner::{
    scan_directory_tree, ImportTreePreview, KindCounts, ScanOptions, ScannedFolderSummary,
    ScannedItem,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
pub use wal::{ImportWal, WalItem};

/// States of the transactional recursive import state machine.
/// Source originals are never eligible for deletion prior to `CatalogCommitted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportState {
    ScanningTree,
    PreviewReady,
    ImportingChunks,
    VerifyingTags,
    CatalogCommitted,
    OptionalSourceCleanup,
    Completed,
    Quarantined,
    Paused,
    Aborted,
}

/// Deduplication policy when a keyed BLAKE3 match already exists inside the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DedupPolicy {
    SkipDuplicate,
    LinkIntoTargetFolder,
    KeepIndependentCopy,
}

/// Write-Ahead Log record written to `wal/import.wal` for crash-safe resumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportWalRecord {
    pub job_id: Uuid,
    pub item_id: Uuid,
    pub target_folder_id: Uuid,
    pub state: ImportState,
    pub verified_chunks: u64,
    pub total_chunks: u64,
    pub timestamp_unix_ms: u64,
}
