use std::fmt;

use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
use crate::keys::{KeyWrappingKey, KEY_LEN};
use crate::recovery_words::RECOVERY_WORDLIST;

/// Number of words in a 256-bit MeshVault Emergency Recovery Kit mnemonic.
pub const RECOVERY_WORD_COUNT: usize = 24;

const RECOVERY_KEK_CONTEXT: &str = "MeshVault v1 Emergency Recovery Kit KEK";

/// Offline 24-word Emergency Recovery Kit encoding 256 bits of entropy plus an 8-bit checksum.
pub struct RecoveryKit {
    entropy: SecretBox<[u8; KEY_LEN]>,
}

impl RecoveryKit {
    /// Generates a new cryptographically random 256-bit Recovery Kit.
    pub fn generate() -> Self {
        let mut entropy = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut *entropy);
        Self {
            entropy: SecretBox::new(Box::new(*entropy)),
        }
    }

    /// Encodes the 256-bit entropy and 8-bit SHA-256 checksum into 24 BIP-39 words.
    pub fn to_mnemonic(&self) -> Zeroizing<String> {
        let secret = self.entropy.expose_secret();
        let checksum = Sha256::digest(secret)[0];

        let mut packed = Zeroizing::new([0u8; KEY_LEN + 1]);
        packed[..KEY_LEN].copy_from_slice(secret);
        packed[KEY_LEN] = checksum;

        let mut words = Vec::with_capacity(RECOVERY_WORD_COUNT);
        for word_pos in 0..RECOVERY_WORD_COUNT {
            let start_bit = word_pos * 11;
            let mut idx: usize = 0;
            for offset in 0..11 {
                let bit_pos = start_bit + offset;
                let byte = packed[bit_pos / 8];
                let bit = (byte >> (7 - (bit_pos % 8))) & 1;
                idx = (idx << 1) | usize::from(bit);
            }
            words.push(RECOVERY_WORDLIST[idx]);
        }

        Zeroizing::new(words.join(" "))
    }

    /// Parses and checksum-validates a 24-word Recovery Kit mnemonic phrase.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, CryptoError> {
        let tokens: Vec<String> = phrase
            .split_whitespace()
            .map(|w| w.trim().to_ascii_lowercase())
            .collect();

        if tokens.len() != RECOVERY_WORD_COUNT {
            return Err(CryptoError::InvalidRecoveryMnemonic(format!(
                "expected {RECOVERY_WORD_COUNT} words, got {}",
                tokens.len()
            )));
        }

        let mut packed = Zeroizing::new([0u8; KEY_LEN + 1]);
        for (word_pos, token) in tokens.iter().enumerate() {
            let idx = RECOVERY_WORDLIST
                .binary_search(&token.as_str())
                .map_err(|_| {
                    CryptoError::InvalidRecoveryMnemonic(format!(
                        "unknown word at position {}",
                        word_pos + 1
                    ))
                })?;

            let start_bit = word_pos * 11;
            for offset in 0..11 {
                let bit_pos = start_bit + offset;
                let bit = ((idx >> (10 - offset)) & 1) as u8;
                packed[bit_pos / 8] |= bit << (7 - (bit_pos % 8));
            }
        }

        let expected_checksum = Sha256::digest(&packed[..KEY_LEN])[0];
        if packed[KEY_LEN] != expected_checksum {
            return Err(CryptoError::InvalidRecoveryMnemonic(
                "recovery phrase checksum mismatch".to_string(),
            ));
        }

        let mut entropy = Zeroizing::new([0u8; KEY_LEN]);
        entropy.copy_from_slice(&packed[..KEY_LEN]);
        Ok(Self {
            entropy: SecretBox::new(Box::new(*entropy)),
        })
    }

    /// Derives the 256-bit Key Wrapping Key (KEK) bound to a specific vault salt.
    pub fn derive_kek(&self, slot_salt: &[u8; 32]) -> KeyWrappingKey {
        let mut hasher = blake3::Hasher::new_derive_key(RECOVERY_KEK_CONTEXT);
        hasher.update(self.entropy.expose_secret());
        hasher.update(slot_salt);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        out.copy_from_slice(hasher.finalize().as_bytes());
        KeyWrappingKey::from_bytes(*out)
    }
}

impl Zeroize for RecoveryKit {
    fn zeroize(&mut self) {
        self.entropy.zeroize();
    }
}

impl ZeroizeOnDrop for RecoveryKit {}

impl fmt::Debug for RecoveryKit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKit([REDACTED])")
    }
}
