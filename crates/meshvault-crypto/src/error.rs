use thiserror::Error;

/// Errors produced by cryptographic primitives, key derivation, chunk streams, and vault headers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("AEAD authentication failed or data was tampered")]
    AuthenticationFailed,

    #[error("key derivation failed: {0}")]
    KdfFailed(String),

    #[error("invalid vault header: {0}")]
    InvalidHeader(String),

    #[error("unsupported vault format version: {0}")]
    UnsupportedVersion(u16),

    #[error("no matching key slot found or credentials are invalid")]
    SlotNotFound,

    #[error("cannot remove the last passphrase slot from vault header")]
    LastPassphraseSlot,

    #[error("invalid chunk stream format: {0}")]
    InvalidChunkFormat(String),

    #[error("chunk index {actual} is out of range (expected < {expected})")]
    ChunkIndexOutOfRange { expected: u64, actual: u64 },

    #[error("encrypted stream is truncated or missing final chunk")]
    TruncatedStream,

    #[error("invalid recovery kit mnemonic: {0}")]
    InvalidRecoveryMnemonic(String),
}
