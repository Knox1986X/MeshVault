use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshvault_crypto::{
    derive_kek_from_passphrase, generate_salt, Argon2Params, CryptoError, SecretString, SALT_LEN,
    TAG_LEN, XNONCE_LEN,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::engine::SyncPolicy;
use crate::error::SyncError;

const PROFILE_MAGIC: [u8; 4] = *b"MVPR";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoSortRule {
    pub rule_name: String,
    pub match_extension: Option<String>,
    pub target_folder_path: Vec<String>,
    pub auto_tags: Vec<String>,
}

/// Portable encrypted settings and auto-sort rule profile transferred between independent vaults
/// without ever exporting or exposing any vault's Master Vault Key (MVK).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedVaultProfile {
    pub version: u32,
    pub locale: String,
    pub slideshow_interval_sec: u32,
    pub sync_policy: SyncPolicy,
    pub auto_sort_rules: Vec<AutoSortRule>,
}

/// Seals preferences and auto-sort rules using a transfer passphrase (`Argon2id` + `XChaCha20-Poly1305`).
pub fn seal_vault_profile(
    profile: &EncryptedVaultProfile,
    transfer_passphrase: &SecretString,
    argon2_params: Argon2Params,
) -> Result<Vec<u8>, SyncError> {
    let salt = generate_salt();
    let kek = derive_kek_from_passphrase(transfer_passphrase, &salt, argon2_params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(kek.expose())
        .map_err(|_| SyncError::InvalidManifest("invalid profile key".to_string()))?;

    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let params_json = serde_json::to_vec(&argon2_params)?;
    let params_len = (params_json.len() as u16).to_le_bytes();

    let mut aad = Vec::with_capacity(4 + 2 + params_json.len() + SALT_LEN);
    aad.extend_from_slice(&PROFILE_MAGIC);
    aad.extend_from_slice(&params_len);
    aad.extend_from_slice(&params_json);
    aad.extend_from_slice(&salt);

    let plain = Zeroizing::new(serde_json::to_vec(profile)?);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plain.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    let mut out = Vec::with_capacity(aad.len() + XNONCE_LEN + ct.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens a portable encrypted profile using the transfer passphrase.
pub fn open_vault_profile(
    sealed: &[u8],
    transfer_passphrase: &SecretString,
) -> Result<EncryptedVaultProfile, SyncError> {
    if sealed.len() < 6 || sealed[0..4] != PROFILE_MAGIC {
        return Err(SyncError::InvalidManifest(
            "invalid encrypted profile magic".to_string(),
        ));
    }
    let params_len = u16::from_le_bytes([sealed[4], sealed[5]]) as usize;
    let header_end = 6 + params_len + SALT_LEN;
    if sealed.len() < header_end + XNONCE_LEN + TAG_LEN {
        return Err(SyncError::InvalidManifest(
            "truncated encrypted profile".to_string(),
        ));
    }
    let argon2_params: Argon2Params = serde_json::from_slice(&sealed[6..6 + params_len])?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&sealed[6 + params_len..header_end]);

    let kek = derive_kek_from_passphrase(transfer_passphrase, &salt, argon2_params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(kek.expose())
        .map_err(|_| SyncError::InvalidManifest("invalid profile key".to_string()))?;
    let nonce = XNonce::from_slice(&sealed[header_end..header_end + XNONCE_LEN]);
    let ct = &sealed[header_end + XNONCE_LEN..];

    let plain = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad: &sealed[..header_end],
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    Ok(serde_json::from_slice(&plain)?)
}
