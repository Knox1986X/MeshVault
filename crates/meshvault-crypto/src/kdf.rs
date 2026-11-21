use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{KeyWrappingKey, KEY_LEN};

/// Length of Argon2id salt in bytes.
pub const SALT_LEN: usize = 32;

/// Argon2id key derivation parameters stored in the vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Params {
    /// Production Argon2id defaults (64 MiB RAM, 3 iterations, 1 lane).
    pub const fn production_default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        }
    }

    /// Lightweight parameters reserved strictly for fast automated tests.
    pub const fn fast_test() -> Self {
        Self {
            memory_kib: 4_096,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Validates parameter bounds against minimum safety requirements.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.memory_kib < 1_024 || self.iterations == 0 || self.parallelism == 0 {
            return Err(CryptoError::KdfFailed(
                "Argon2id parameters below minimum bounds".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::production_default()
    }
}

/// Generates a fresh 256-bit cryptographic salt using OsRng.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives a 256-bit Key Wrapping Key (KEK) from a user passphrase via Argon2id.
pub fn derive_kek_from_passphrase(
    passphrase: &SecretString,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
) -> Result<KeyWrappingKey, CryptoError> {
    params.validate()?;
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;

    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    ctx.hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut *out)
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;

    Ok(KeyWrappingKey::from_bytes(*out))
}
