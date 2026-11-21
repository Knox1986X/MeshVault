pub mod backup;
pub mod engine;
pub mod error;
pub mod lan;
pub mod transport;

pub use backup::{export_verified_backup, BackupReport};
pub use engine::{
    decode_cloud_envelope, encode_padded_cloud_envelope, merge_catalogs_lww, DeviceNetworkState,
    EncryptedSyncManifest, RemoteBlobDescriptor, SyncDownloadMode, SyncEngine, SyncPolicy,
    SyncReport,
};
pub use error::SyncError;
pub use lan::{LanPairingQrPayload, LanPairingSession, LanSyncFrame};
use serde::{Deserialize, Serialize};
pub use transport::{
    validate_app_folder_path, InMemoryMockRemote, LocalDirectoryRemote, PkceAuthFlow,
    RemoteSyncTransport, DROPBOX_APP_ROOT,
};
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
