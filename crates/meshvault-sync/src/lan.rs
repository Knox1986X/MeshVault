use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshvault_crypto::{CryptoError, KEY_LEN, XNONCE_LEN};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SyncError;

const LAN_FRAME_MAGIC: [u8; 4] = *b"MVLN";

/// QR pairing descriptor displayed by the initiating peer for Wi-Fi Direct / LAN sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanPairingQrPayload {
    pub vault_id: Uuid,
    pub peer_id: Uuid,
    pub host_port: String,
    pub session_key_hex: String,
    pub verification_sas: String,
}

/// Authenticated and replay-protected frame exchanged over LAN TCP/WebSocket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanSyncFrame {
    pub seq_no: u64,
    pub nonce: [u8; XNONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Ephemeral XChaCha20-Poly1305 channel for direct Android <-> CachyOS LAN synchronization.
pub struct LanPairingSession {
    vault_id: Uuid,
    session_key: [u8; KEY_LEN],
    verification_sas: String,
    tx_seq: u64,
    expected_rx_seq: u64,
}

impl LanPairingSession {
    pub fn initiate(vault_id: Uuid) -> Self {
        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        let sas = compute_sas_code(vault_id, &key);
        Self {
            vault_id,
            session_key: key,
            verification_sas: sas,
            tx_seq: 0,
            expected_rx_seq: 0,
        }
    }

    pub fn join_from_qr(qr: &LanPairingQrPayload) -> Result<Self, SyncError> {
        let bytes = decode_hex_32(&qr.session_key_hex)?;
        let sas = compute_sas_code(qr.vault_id, &bytes);
        if sas != qr.verification_sas {
            return Err(SyncError::Crypto(CryptoError::AuthenticationFailed));
        }
        Ok(Self {
            vault_id: qr.vault_id,
            session_key: bytes,
            verification_sas: sas,
            tx_seq: 0,
            expected_rx_seq: 0,
        })
    }

    pub fn to_qr_payload(
        &self,
        peer_id: Uuid,
        host_port: impl Into<String>,
    ) -> LanPairingQrPayload {
        LanPairingQrPayload {
            vault_id: self.vault_id,
            peer_id,
            host_port: host_port.into(),
            session_key_hex: encode_hex(&self.session_key),
            verification_sas: self.verification_sas.clone(),
        }
    }

    pub fn verification_sas(&self) -> &str {
        &self.verification_sas
    }

    pub fn seal_frame(&mut self, plaintext: &[u8]) -> Result<LanSyncFrame, SyncError> {
        let seq_no = self.tx_seq;
        self.tx_seq = self.tx_seq.saturating_add(1);

        let cipher = XChaCha20Poly1305::new_from_slice(&self.session_key)
            .map_err(|_| SyncError::InvalidManifest("invalid LAN key".to_string()))?;
        let mut nonce = [0u8; XNONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let aad = lan_aad(self.vault_id, seq_no);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(LanSyncFrame {
            seq_no,
            nonce,
            ciphertext,
        })
    }

    pub fn open_frame(&mut self, frame: &LanSyncFrame) -> Result<Vec<u8>, SyncError> {
        if frame.seq_no != self.expected_rx_seq {
            return Err(SyncError::LanSequenceMismatch {
                expected: self.expected_rx_seq,
                actual: frame.seq_no,
            });
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&self.session_key)
            .map_err(|_| SyncError::InvalidManifest("invalid LAN key".to_string()))?;
        let aad = lan_aad(self.vault_id, frame.seq_no);
        let plain = cipher
            .decrypt(
                XNonce::from_slice(&frame.nonce),
                Payload {
                    msg: &frame.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        self.expected_rx_seq = self.expected_rx_seq.saturating_add(1);
        Ok(plain)
    }
}

impl Zeroize for LanPairingSession {
    fn zeroize(&mut self) {
        self.session_key.zeroize();
    }
}

impl ZeroizeOnDrop for LanPairingSession {}

fn compute_sas_code(vault_id: Uuid, session_key: &[u8; KEY_LEN]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("MeshVault v1 LAN QR SAS");
    hasher.update(vault_id.as_bytes());
    hasher.update(session_key);
    let hash = hasher.finalize();
    let b = hash.as_bytes();
    let code = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) % 1_000_000;
    format!("{code:06}")
}

fn lan_aad(vault_id: Uuid, seq_no: u64) -> [u8; 28] {
    let mut aad = [0u8; 28];
    aad[0..4].copy_from_slice(&LAN_FRAME_MAGIC);
    aad[4..20].copy_from_slice(vault_id.as_bytes());
    aad[20..28].copy_from_slice(&seq_no.to_le_bytes());
    aad
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 0x0f) as usize]));
    }
    out
}

fn decode_hex_32(hex: &str) -> Result<[u8; KEY_LEN], SyncError> {
    if hex.len() != KEY_LEN * 2 {
        return Err(SyncError::InvalidManifest(
            "invalid hex session key length".to_string(),
        ));
    }
    let mut out = [0u8; KEY_LEN];
    let bytes = hex.as_bytes();
    for i in 0..KEY_LEN {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, SyncError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(SyncError::InvalidManifest("invalid hex digit".to_string())),
    }
}
