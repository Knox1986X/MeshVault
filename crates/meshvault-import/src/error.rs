use meshvault_crypto::CryptoError;
use meshvault_storage::StorageError;
use thiserror::Error;

/// Errors produced during recursive tree scanning, metadata extraction, WAL persistence, or chunked import.
#[derive(Debug, Error)]
pub enum ImportError {
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("WAL serialization error: {0}")]
    WalFormat(String),

    #[error("tree depth limit exceeded at {0}")]
    MaxDepthExceeded(String),

    #[error("source path is not a directory: {0}")]
    NotADirectory(String),

    #[error("no active WAL found to resume")]
    NoActiveWal,

    #[error("simulated process crash after processing {processed} items")]
    SimulatedCrash { processed: usize },

    #[error("invalid image payload: {0}")]
    InvalidImage(String),
}
