pub mod chunk;
pub mod error;
pub mod header;
pub mod kdf;
pub mod keys;
pub mod mem_guard;
pub mod recovery;
mod recovery_words;

pub use chunk::{
    build_chunk_aad, decrypt_chunk, derive_chunk_nonce, encrypt_chunk, encrypt_stream, BlobPrelude,
    ChunkedBlobReader, BLOB_MAGIC, BLOB_PRELUDE_LEN, DEFAULT_CHUNK_SIZE,
};
pub use error::CryptoError;
pub use header::{
    KeySlot, SlotType, VaultHeader, FLAG_DECOY_AWARE, FLAG_SIZE_PADDING, HEADER_FORMAT_VERSION,
    HEADER_MAGIC,
};
pub use kdf::{derive_kek_from_passphrase, generate_salt, Argon2Params, SALT_LEN};
pub use keys::{
    unwrap_fek, wrap_fek, DerivedSubkey, FileEncryptionKey, KeyWrappingKey, MasterVaultKey,
    KEY_LEN, TAG_LEN, WRAPPED_FEK_LEN, XNONCE_LEN,
};
pub use mem_guard::{disable_core_dumps, lock_slice_in_ram, unlock_slice_in_ram, LockedSecretBox};
pub use recovery::{RecoveryKit, RECOVERY_WORD_COUNT};
pub use secrecy::{ExposeSecret, SecretString};
pub use zeroize::{Zeroize, Zeroizing};
