use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;
use crate::kdf::{derive_kek_from_passphrase, generate_salt, Argon2Params, SALT_LEN};
use crate::keys::{KeyWrappingKey, MasterVaultKey, KEY_LEN, TAG_LEN, XNONCE_LEN};
use crate::recovery::RecoveryKit;

/// Magic bytes identifying a MeshVault Format v1 header.
pub const HEADER_MAGIC: [u8; 4] = *b"MVLT";

/// Current binary vault header format version.
pub const HEADER_FORMAT_VERSION: u16 = 1;

/// Fixed byte length of the header prefix before key slots.
pub const HEADER_PREFIX_LEN: usize = 54;

/// Fixed byte length of each serialized key slot record.
pub const KEY_SLOT_LEN: usize = 121;

/// Size of wrapped MVK ciphertext + Poly1305 tag inside a key slot.
pub const WRAPPED_MVK_LEN: usize = KEY_LEN + TAG_LEN;

/// Header flag: pad media chunks/packs to reduce cloud size fingerprinting.
pub const FLAG_SIZE_PADDING: u16 = 1 << 0;

/// Header flag: indicates a vault configured with decoy-aware metadata layout.
pub const FLAG_DECOY_AWARE: u16 = 1 << 1;

const SLOT_AAD_PREFIX: &[u8] = b"MVLT-SLOT-V1";

/// Kind of key slot wrapping the Master Vault Key (MVK).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SlotType {
    PassphraseArgon2id = 1,
    HardwareKeystore = 2,
    RecoveryKit24 = 3,
    Fido2Hmac = 4,
    DecoyPassphrase = 5,
}

impl SlotType {
    fn from_u8(val: u8) -> Result<Self, CryptoError> {
        match val {
            1 => Ok(Self::PassphraseArgon2id),
            2 => Ok(Self::HardwareKeystore),
            3 => Ok(Self::RecoveryKit24),
            4 => Ok(Self::Fido2Hmac),
            5 => Ok(Self::DecoyPassphrase),
            other => Err(CryptoError::InvalidHeader(format!(
                "unknown key slot type: {other}"
            ))),
        }
    }
}

/// Independent key slot storing an AEAD-wrapped copy of the Master Vault Key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySlot {
    pub slot_id: Uuid,
    pub slot_type: SlotType,
    pub salt: [u8; SALT_LEN],
    pub wrap_nonce: [u8; XNONCE_LEN],
    pub wrapped_mvk: [u8; WRAPPED_MVK_LEN],
}

/// Authenticated binary header (`vault.header` / `vault.header.bak`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub format_version: u16,
    pub flags: u16,
    pub vault_id: Uuid,
    pub revision: u64,
    pub created_at_unix_ms: u64,
    pub argon2_params: Argon2Params,
    pub slots: Vec<KeySlot>,
}

impl VaultHeader {
    /// Creates a new vault header with an initial Argon2id passphrase slot and returns `(header, mvk)`.
    pub fn create_with_passphrase(
        passphrase: &SecretString,
        argon2_params: Argon2Params,
        created_at_unix_ms: u64,
        flags: u16,
    ) -> Result<(Self, MasterVaultKey), CryptoError> {
        argon2_params.validate()?;
        let mvk = MasterVaultKey::generate();
        let vault_id = Uuid::new_v4();
        let salt = generate_salt();
        let kek = derive_kek_from_passphrase(passphrase, &salt, argon2_params)?;

        let slot = wrap_mvk_into_slot(
            vault_id,
            HEADER_FORMAT_VERSION,
            SlotType::PassphraseArgon2id,
            salt,
            &kek,
            &mvk,
        )?;

        let header = Self {
            format_version: HEADER_FORMAT_VERSION,
            flags,
            vault_id,
            revision: 1,
            created_at_unix_ms,
            argon2_params,
            slots: vec![slot],
        };

        Ok((header, mvk))
    }

    /// Unlocks the Master Vault Key using a passphrase against any PassphraseArgon2id slot.
    pub fn unlock_with_passphrase(
        &self,
        passphrase: &SecretString,
    ) -> Result<MasterVaultKey, CryptoError> {
        for slot in &self.slots {
            if slot.slot_type == SlotType::PassphraseArgon2id {
                let kek = derive_kek_from_passphrase(passphrase, &slot.salt, self.argon2_params)?;
                if let Ok(mvk) =
                    unwrap_mvk_from_slot(self.vault_id, self.format_version, slot, &kek)
                {
                    return Ok(mvk);
                }
            }
        }
        Err(CryptoError::SlotNotFound)
    }

    /// Unlocks the Master Vault Key using an Emergency Recovery Kit (24 words).
    pub fn unlock_with_recovery_kit(
        &self,
        kit: &RecoveryKit,
    ) -> Result<MasterVaultKey, CryptoError> {
        for slot in &self.slots {
            if slot.slot_type == SlotType::RecoveryKit24 {
                let kek = kit.derive_kek(&slot.salt);
                if let Ok(mvk) =
                    unwrap_mvk_from_slot(self.vault_id, self.format_version, slot, &kek)
                {
                    return Ok(mvk);
                }
            }
        }
        Err(CryptoError::SlotNotFound)
    }

    /// Unlocks the Master Vault Key using a hardware-backed or FIDO2 wrapping key.
    pub fn unlock_with_wrapping_key(
        &self,
        slot_id: Uuid,
        kek: &KeyWrappingKey,
    ) -> Result<MasterVaultKey, CryptoError> {
        let slot = self
            .slots
            .iter()
            .find(|s| s.slot_id == slot_id)
            .ok_or(CryptoError::SlotNotFound)?;

        unwrap_mvk_from_slot(self.vault_id, self.format_version, slot, kek)
            .map_err(|_| CryptoError::SlotNotFound)
    }

    /// Adds a Recovery Kit slot to the header and increments header revision.
    pub fn add_recovery_slot(
        &mut self,
        mvk: &MasterVaultKey,
        kit: &RecoveryKit,
    ) -> Result<Uuid, CryptoError> {
        let salt = generate_salt();
        let kek = kit.derive_kek(&salt);
        let slot = wrap_mvk_into_slot(
            self.vault_id,
            self.format_version,
            SlotType::RecoveryKit24,
            salt,
            &kek,
            mvk,
        )?;
        let slot_id = slot.slot_id;
        self.slots.push(slot);
        self.revision = self.revision.saturating_add(1);
        Ok(slot_id)
    }

    /// Adds a hardware keystore (Android Keystore / Secret Service) wrapping slot.
    pub fn add_hardware_slot(
        &mut self,
        mvk: &MasterVaultKey,
        hardware_kek: &KeyWrappingKey,
    ) -> Result<Uuid, CryptoError> {
        let salt = generate_salt();
        let slot = wrap_mvk_into_slot(
            self.vault_id,
            self.format_version,
            SlotType::HardwareKeystore,
            salt,
            hardware_kek,
            mvk,
        )?;
        let slot_id = slot.slot_id;
        self.slots.push(slot);
        self.revision = self.revision.saturating_add(1);
        Ok(slot_id)
    }

    /// Rotates the passphrase in milliseconds by re-wrapping only the header slot (media untouched).
    pub fn rotate_passphrase(
        &mut self,
        old_passphrase: &SecretString,
        new_passphrase: &SecretString,
        new_params: Option<Argon2Params>,
    ) -> Result<(), CryptoError> {
        let mvk = self.unlock_with_passphrase(old_passphrase)?;
        let params = new_params.unwrap_or(self.argon2_params);
        params.validate()?;

        let salt = generate_salt();
        let new_kek = derive_kek_from_passphrase(new_passphrase, &salt, params)?;
        let new_slot = wrap_mvk_into_slot(
            self.vault_id,
            self.format_version,
            SlotType::PassphraseArgon2id,
            salt,
            &new_kek,
            &mvk,
        )?;

        self.slots
            .retain(|s| s.slot_type != SlotType::PassphraseArgon2id);
        self.slots.insert(0, new_slot);
        self.argon2_params = params;
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Removes a non-last key slot by ID and increments header revision.
    pub fn remove_slot(&mut self, slot_id: Uuid) -> Result<(), CryptoError> {
        let Some(pos) = self.slots.iter().position(|s| s.slot_id == slot_id) else {
            return Err(CryptoError::SlotNotFound);
        };
        if self.slots[pos].slot_type == SlotType::PassphraseArgon2id {
            let passphrase_count = self
                .slots
                .iter()
                .filter(|s| s.slot_type == SlotType::PassphraseArgon2id)
                .count();
            if passphrase_count <= 1 {
                return Err(CryptoError::LastPassphraseSlot);
            }
        }
        self.slots.remove(pos);
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Serializes the header into canonical binary format with a trailing BLAKE3 integrity digest.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let slot_count = u16::try_from(self.slots.len())
            .map_err(|_| CryptoError::InvalidHeader("too many key slots".to_string()))?;

        let total_len = HEADER_PREFIX_LEN + self.slots.len() * KEY_SLOT_LEN + KEY_LEN;
        let mut out = Vec::with_capacity(total_len);

        out.extend_from_slice(&HEADER_MAGIC);
        out.extend_from_slice(&self.format_version.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(&self.revision.to_le_bytes());
        out.extend_from_slice(&self.created_at_unix_ms.to_le_bytes());
        out.extend_from_slice(&self.argon2_params.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.argon2_params.iterations.to_le_bytes());
        out.extend_from_slice(&self.argon2_params.parallelism.to_le_bytes());
        out.extend_from_slice(&slot_count.to_le_bytes());

        for slot in &self.slots {
            out.extend_from_slice(slot.slot_id.as_bytes());
            out.push(slot.slot_type as u8);
            out.extend_from_slice(&slot.salt);
            out.extend_from_slice(&slot.wrap_nonce);
            out.extend_from_slice(&slot.wrapped_mvk);
        }

        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        Ok(out)
    }

    /// Parses and integrity-checks a serialized vault header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < HEADER_PREFIX_LEN + KEY_LEN {
            return Err(CryptoError::InvalidHeader(
                "header shorter than minimum length".to_string(),
            ));
        }
        if bytes[0..4] != HEADER_MAGIC {
            return Err(CryptoError::InvalidHeader(
                "invalid vault header magic".to_string(),
            ));
        }

        let body_len = bytes.len() - KEY_LEN;
        let expected_digest = blake3::hash(&bytes[..body_len]);
        if expected_digest.as_bytes() != &bytes[body_len..] {
            return Err(CryptoError::InvalidHeader(
                "header integrity digest mismatch".to_string(),
            ));
        }

        let format_version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if format_version != HEADER_FORMAT_VERSION {
            return Err(CryptoError::UnsupportedVersion(format_version));
        }
        let flags = u16::from_le_bytes([bytes[6], bytes[7]]);

        let mut vault_id_bytes = [0u8; 16];
        vault_id_bytes.copy_from_slice(&bytes[8..24]);
        let vault_id = Uuid::from_bytes(vault_id_bytes);

        let revision = u64::from_le_bytes(read_8(&bytes[24..32]));
        let created_at_unix_ms = u64::from_le_bytes(read_8(&bytes[32..40]));
        let memory_kib = u32::from_le_bytes(read_4(&bytes[40..44]));
        let iterations = u32::from_le_bytes(read_4(&bytes[44..48]));
        let parallelism = u32::from_le_bytes(read_4(&bytes[48..52]));
        let argon2_params = Argon2Params {
            memory_kib,
            iterations,
            parallelism,
        };
        argon2_params.validate()?;

        let slot_count = u16::from_le_bytes([bytes[52], bytes[53]]) as usize;
        let expected_body_len = HEADER_PREFIX_LEN + slot_count * KEY_SLOT_LEN;
        if body_len != expected_body_len {
            return Err(CryptoError::InvalidHeader(
                "header length does not match slot_count".to_string(),
            ));
        }

        let mut slots = Vec::with_capacity(slot_count);
        let mut cursor = HEADER_PREFIX_LEN;
        for _ in 0..slot_count {
            let mut slot_id_bytes = [0u8; 16];
            slot_id_bytes.copy_from_slice(&bytes[cursor..cursor + 16]);
            let slot_id = Uuid::from_bytes(slot_id_bytes);
            let slot_type = SlotType::from_u8(bytes[cursor + 16])?;

            let mut salt = [0u8; SALT_LEN];
            salt.copy_from_slice(&bytes[cursor + 17..cursor + 49]);

            let mut wrap_nonce = [0u8; XNONCE_LEN];
            wrap_nonce.copy_from_slice(&bytes[cursor + 49..cursor + 73]);

            let mut wrapped_mvk = [0u8; WRAPPED_MVK_LEN];
            wrapped_mvk.copy_from_slice(&bytes[cursor + 73..cursor + 121]);

            slots.push(KeySlot {
                slot_id,
                slot_type,
                salt,
                wrap_nonce,
                wrapped_mvk,
            });
            cursor += KEY_SLOT_LEN;
        }

        Ok(Self {
            format_version,
            flags,
            vault_id,
            revision,
            created_at_unix_ms,
            argon2_params,
            slots,
        })
    }

    /// Selects the newest valid header between `vault.header` and `vault.header.bak`.
    pub fn select_latest_valid(
        primary: Option<&[u8]>,
        backup: Option<&[u8]>,
    ) -> Result<Self, CryptoError> {
        let parsed_primary = primary.and_then(|b| Self::from_bytes(b).ok());
        let parsed_backup = backup.and_then(|b| Self::from_bytes(b).ok());

        match (parsed_primary, parsed_backup) {
            (Some(p), Some(b)) => {
                if b.revision > p.revision {
                    Ok(b)
                } else {
                    Ok(p)
                }
            }
            (Some(p), None) => Ok(p),
            (None, Some(b)) => Ok(b),
            (None, None) => Err(CryptoError::InvalidHeader(
                "neither primary nor backup vault header is valid".to_string(),
            )),
        }
    }
}

fn wrap_mvk_into_slot(
    vault_id: Uuid,
    format_version: u16,
    slot_type: SlotType,
    salt: [u8; SALT_LEN],
    kek: &KeyWrappingKey,
    mvk: &MasterVaultKey,
) -> Result<KeySlot, CryptoError> {
    let slot_id = Uuid::new_v4();
    let cipher = XChaCha20Poly1305::new_from_slice(kek.expose())
        .map_err(|_| CryptoError::InvalidHeader("invalid KEK length".to_string()))?;

    let mut wrap_nonce = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut wrap_nonce);
    let nonce = XNonce::from_slice(&wrap_nonce);
    let aad = build_slot_aad(vault_id, format_version, slot_id, slot_type);

    let encrypted = cipher
        .encrypt(
            nonce,
            Payload {
                msg: mvk.expose().as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    if encrypted.len() != WRAPPED_MVK_LEN {
        return Err(CryptoError::InvalidHeader(
            "unexpected wrapped MVK length".to_string(),
        ));
    }

    let mut wrapped_mvk = [0u8; WRAPPED_MVK_LEN];
    wrapped_mvk.copy_from_slice(&encrypted);

    Ok(KeySlot {
        slot_id,
        slot_type,
        salt,
        wrap_nonce,
        wrapped_mvk,
    })
}

fn unwrap_mvk_from_slot(
    vault_id: Uuid,
    format_version: u16,
    slot: &KeySlot,
    kek: &KeyWrappingKey,
) -> Result<MasterVaultKey, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(kek.expose())
        .map_err(|_| CryptoError::InvalidHeader("invalid KEK length".to_string()))?;

    let nonce = XNonce::from_slice(&slot.wrap_nonce);
    let aad = build_slot_aad(vault_id, format_version, slot.slot_id, slot.slot_type);

    let mut plain = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &slot.wrapped_mvk,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );

    if plain.len() != KEY_LEN {
        plain.zeroize();
        return Err(CryptoError::AuthenticationFailed);
    }

    let mut raw = Zeroizing::new([0u8; KEY_LEN]);
    raw.copy_from_slice(&plain);
    Ok(MasterVaultKey::from_bytes(*raw))
}

fn build_slot_aad(
    vault_id: Uuid,
    format_version: u16,
    slot_id: Uuid,
    slot_type: SlotType,
) -> [u8; 47] {
    let mut aad = [0u8; 47];
    aad[0..12].copy_from_slice(SLOT_AAD_PREFIX);
    aad[12..28].copy_from_slice(vault_id.as_bytes());
    aad[28..30].copy_from_slice(&format_version.to_le_bytes());
    aad[30..46].copy_from_slice(slot_id.as_bytes());
    aad[46] = slot_type as u8;
    aad
}

fn read_4(slice: &[u8]) -> [u8; 4] {
    [slice[0], slice[1], slice[2], slice[3]]
}

fn read_8(slice: &[u8]) -> [u8; 8] {
    [
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]
}
