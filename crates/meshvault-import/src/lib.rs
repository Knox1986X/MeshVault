use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
