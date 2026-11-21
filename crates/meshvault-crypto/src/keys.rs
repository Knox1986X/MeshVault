use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;

/// Length of symmetric 256-bit keys used across MeshVault.
pub const KEY_LEN: usize = 32;

/// Length of an XChaCha20-Poly1305 extended nonce (192 bits).
pub const XNONCE_LEN: usize = 24;

/// Length of a Poly1305 authentication tag (128 bits).
pub const TAG_LEN: usize = 16;

/// Length of a wrapped FEK envelope: 24-byte nonce + 32-byte key + 16-byte Poly1305 tag.
pub const WRAPPED_FEK_LEN: usize = XNONCE_LEN + KEY_LEN + TAG_LEN;

const FEK_WRAP_AAD_PREFIX: &[u8] = b"MVLT-FEK-WRAP-V1";
const SUBKEY_CATALOG_CONTEXT: &str = "MeshVault v1 Catalog Master Key";
const SUBKEY_DEDUP_CONTEXT: &str = "MeshVault v1 Keyed Dedup BLAKE3";
const SUBKEY_SEARCH_CONTEXT: &str = "MeshVault v1 Search Index Key";
const SUBKEY_THUMB_INDEX_CONTEXT: &str = "MeshVault v1 Thumbnail Index Key";
const SUBKEY_AUDIT_CONTEXT: &str = "MeshVault v1 Security Audit Log Key";

/// Master Vault Key (MVK) held exclusively in RAM while a vault is unlocked.
pub struct MasterVaultKey {
    inner: SecretBox<[u8; KEY_LEN]>,
}

impl MasterVaultKey {
    /// Generates a fresh 256-bit Master Vault Key using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut raw = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut *raw);
        Self::from_bytes(*raw)
    }

    /// Constructs a Master Vault Key from raw 32-byte key material.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            inner: SecretBox::new(Box::new(bytes)),
        }
    }

    /// Exposes the raw 32-byte MVK slice for internal cryptographic operations.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        self.inner.expose_secret()
    }

    /// Derives a domain-separated 256-bit subkey for a specific subsystem.
    pub fn derive_subkey(&self, domain_context: &str, extra_context: &[u8]) -> DerivedSubkey {
        let mut hasher = blake3::Hasher::new_derive_key(domain_context);
        hasher.update(self.expose());
        hasher.update(extra_context);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        out.copy_from_slice(hasher.finalize().as_bytes());
        DerivedSubkey::from_bytes(*out)
    }

    /// Derives the key protecting the encrypted hierarchical folder and media catalog.
    pub fn derive_catalog_key(&self) -> DerivedSubkey {
        self.derive_subkey(SUBKEY_CATALOG_CONTEXT, b"catalog-v1")
    }

    /// Derives the keyed BLAKE3 deduplication key so file fingerprints remain vault-private.
    pub fn derive_dedup_key(&self) -> DerivedSubkey {
        self.derive_subkey(SUBKEY_DEDUP_CONTEXT, b"dedup-v1")
    }

    /// Derives the key for the encrypted local search and OCR token index.
    pub fn derive_search_index_key(&self) -> DerivedSubkey {
        self.derive_subkey(SUBKEY_SEARCH_CONTEXT, b"search-v1")
    }

    /// Derives the key for thumbnail pack metadata entries.
    pub fn derive_thumb_index_key(&self) -> DerivedSubkey {
        self.derive_subkey(SUBKEY_THUMB_INDEX_CONTEXT, b"thumbs-v1")
    }

    /// Derives the key for the encrypted local security audit log.
    pub fn derive_audit_log_key(&self) -> DerivedSubkey {
        self.derive_subkey(SUBKEY_AUDIT_CONTEXT, b"audit-v1")
    }

    /// Computes a vault-scoped keyed BLAKE3 fingerprint for duplicate detection.
    pub fn keyed_dedup_hash(&self, plaintext: &[u8]) -> [u8; KEY_LEN] {
        let dedup_key = self.derive_dedup_key();
        *blake3::keyed_hash(dedup_key.expose(), plaintext).as_bytes()
    }
}

impl Zeroize for MasterVaultKey {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl ZeroizeOnDrop for MasterVaultKey {}

impl fmt::Debug for MasterVaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterVaultKey([REDACTED])")
    }
}

/// Per-file or per-pack 256-bit File Encryption Key (FEK).
pub struct FileEncryptionKey {
    inner: SecretBox<[u8; KEY_LEN]>,
}

impl FileEncryptionKey {
    /// Generates a fresh random 256-bit FEK using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut raw = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut *raw);
        Self::from_bytes(*raw)
    }

    /// Constructs an FEK from raw 32-byte key material.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            inner: SecretBox::new(Box::new(bytes)),
        }
    }

    /// Exposes the raw 32-byte FEK slice.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        self.inner.expose_secret()
    }
}

impl Zeroize for FileEncryptionKey {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl ZeroizeOnDrop for FileEncryptionKey {}

impl fmt::Debug for FileEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileEncryptionKey([REDACTED])")
    }
}

/// Key Wrapping Key (KEK) derived from a passphrase, hardware keystore, or Recovery Kit.
pub struct KeyWrappingKey {
    inner: SecretBox<[u8; KEY_LEN]>,
}

impl KeyWrappingKey {
    /// Constructs a KEK from raw 32-byte key material.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            inner: SecretBox::new(Box::new(bytes)),
        }
    }

    /// Generates a random 256-bit KEK (for example, to bind with Android Keystore).
    pub fn generate() -> Self {
        let mut raw = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut *raw);
        Self::from_bytes(*raw)
    }

    /// Exposes the raw 32-byte KEK slice.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        self.inner.expose_secret()
    }
}

impl Zeroize for KeyWrappingKey {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl ZeroizeOnDrop for KeyWrappingKey {}

impl fmt::Debug for KeyWrappingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyWrappingKey([REDACTED])")
    }
}

/// Domain-separated 256-bit derived subkey.
pub struct DerivedSubkey {
    inner: SecretBox<[u8; KEY_LEN]>,
}

impl DerivedSubkey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self {
            inner: SecretBox::new(Box::new(bytes)),
        }
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        self.inner.expose_secret()
    }
}

impl Zeroize for DerivedSubkey {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl ZeroizeOnDrop for DerivedSubkey {}

impl fmt::Debug for DerivedSubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedSubkey([REDACTED])")
    }
}

/// Wraps a File Encryption Key (FEK) under the Master Vault Key (MVK) using XChaCha20-Poly1305.
pub fn wrap_fek(
    mvk: &MasterVaultKey,
    file_id: Uuid,
    fek: &FileEncryptionKey,
) -> Result<[u8; WRAPPED_FEK_LEN], CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(mvk.expose())
        .map_err(|_| CryptoError::InvalidHeader("invalid MVK length".to_string()))?;

    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let aad = fek_wrap_aad(file_id);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: fek.expose().as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let mut out = [0u8; WRAPPED_FEK_LEN];
    out[..XNONCE_LEN].copy_from_slice(&nonce_bytes);
    out[XNONCE_LEN..].copy_from_slice(&ciphertext);
    Ok(out)
}

/// Unwraps a File Encryption Key (FEK) using the Master Vault Key (MVK).
pub fn unwrap_fek(
    mvk: &MasterVaultKey,
    file_id: Uuid,
    wrapped: &[u8; WRAPPED_FEK_LEN],
) -> Result<FileEncryptionKey, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(mvk.expose())
        .map_err(|_| CryptoError::InvalidHeader("invalid MVK length".to_string()))?;

    let nonce = XNonce::from_slice(&wrapped[..XNONCE_LEN]);
    let ciphertext = &wrapped[XNONCE_LEN..];
    let aad = fek_wrap_aad(file_id);

    let mut plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    if plain.len() != KEY_LEN {
        plain.zeroize();
        return Err(CryptoError::AuthenticationFailed);
    }

    let mut raw = [0u8; KEY_LEN];
    raw.copy_from_slice(&plain);
    plain.zeroize();
    let fek = FileEncryptionKey::from_bytes(raw);
    raw.zeroize();
    Ok(fek)
}

fn fek_wrap_aad(file_id: Uuid) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[..16].copy_from_slice(FEK_WRAP_AAD_PREFIX);
    aad[16..].copy_from_slice(file_id.as_bytes());
    aad
}
