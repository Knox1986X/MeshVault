use meshvault_crypto::CryptoError;
use meshvault_storage::StorageError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("remote object not found: {0}")]
    RemoteNotFound(String),

    #[error("invalid remote path outside /MeshVault/ scope: {0}")]
    ScopeViolation(String),

    #[error("invalid sync manifest: {0}")]
    InvalidManifest(String),

    #[error("LAN frame replay or sequence mismatch (expected {expected}, got {actual})")]
    LanSequenceMismatch { expected: u64, actual: u64 },
}
