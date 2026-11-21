use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// States of the zero-knowledge cloud and LAN synchronization state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    IdleOffline,
    CheckingRemoteEpoch,
    UploadingBlobs,
    DownloadingMissingManifest,
    MergingCatalog,
    AtomicEpochCommit,
    Synced,
    PausedMetered,
    ConflictResolved,
}

/// Remote zero-knowledge manifest published under `/MeshVault/` in Dropbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteManifestHeader {
    pub vault_id: Uuid,
    pub epoch: u64,
    pub catalog_blob_hash: [u8; 32],
    pub encrypted_blob_count: u64,
}
