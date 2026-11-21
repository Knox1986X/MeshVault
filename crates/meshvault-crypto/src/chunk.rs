use std::io::{Read, Seek, SeekFrom, Write};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{FileEncryptionKey, TAG_LEN, XNONCE_LEN};

/// Default plaintext chunk size: 1 MiB.
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Magic bytes identifying a MeshVault Format v1 chunked media blob.
pub const BLOB_MAGIC: [u8; 4] = *b"MVB1";

/// Fixed length of the binary prelude at the start of every encrypted media blob.
pub const BLOB_PRELUDE_LEN: usize = 48;

const CHUNK_NONCE_CONTEXT: &str = "MeshVault v1 Chunk Nonce";
const CHUNK_AAD_LEN: usize = 33;

/// Fixed 48-byte prelude written at offset 0 of every chunked blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobPrelude {
    pub file_id: Uuid,
    pub chunk_size: u32,
    pub base_nonce: [u8; XNONCE_LEN],
}

impl BlobPrelude {
    /// Creates a new prelude with a fresh random 192-bit base nonce from OsRng.
    pub fn new(file_id: Uuid, chunk_size: u32) -> Result<Self, CryptoError> {
        if chunk_size == 0 {
            return Err(CryptoError::InvalidChunkFormat(
                "chunk_size must be greater than zero".to_string(),
            ));
        }
        let mut base_nonce = [0u8; XNONCE_LEN];
        OsRng.fill_bytes(&mut base_nonce);
        Ok(Self {
            file_id,
            chunk_size,
            base_nonce,
        })
    }

    /// Serializes the prelude to its canonical 48-byte big/little-endian representation.
    pub fn to_bytes(&self) -> [u8; BLOB_PRELUDE_LEN] {
        let mut buf = [0u8; BLOB_PRELUDE_LEN];
        buf[0..4].copy_from_slice(&BLOB_MAGIC);
        buf[4..20].copy_from_slice(self.file_id.as_bytes());
        buf[20..24].copy_from_slice(&self.chunk_size.to_le_bytes());
        buf[24..48].copy_from_slice(&self.base_nonce);
        buf
    }

    /// Parses a 48-byte blob prelude and validates magic and chunk size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < BLOB_PRELUDE_LEN {
            return Err(CryptoError::TruncatedStream);
        }
        if bytes[0..4] != BLOB_MAGIC {
            return Err(CryptoError::InvalidChunkFormat(
                "unexpected blob magic bytes".to_string(),
            ));
        }
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&bytes[4..20]);
        let file_id = Uuid::from_bytes(id_bytes);
        let chunk_size = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        if chunk_size == 0 {
            return Err(CryptoError::InvalidChunkFormat(
                "chunk_size in prelude cannot be zero".to_string(),
            ));
        }
        let mut base_nonce = [0u8; XNONCE_LEN];
        base_nonce.copy_from_slice(&bytes[24..48]);
        Ok(Self {
            file_id,
            chunk_size,
            base_nonce,
        })
    }

    /// Encrypted stride (bytes on disk) for every non-final chunk.
    pub fn encrypted_stride(&self) -> u64 {
        u64::from(self.chunk_size) + TAG_LEN as u64
    }

    /// Computes total chunk count from total encrypted blob length in bytes.
    pub fn total_chunks_from_blob_len(&self, blob_len: u64) -> Result<u64, CryptoError> {
        if blob_len < BLOB_PRELUDE_LEN as u64 + TAG_LEN as u64 {
            return Err(CryptoError::TruncatedStream);
        }
        let payload_len = blob_len - BLOB_PRELUDE_LEN as u64;
        let stride = self.encrypted_stride();
        Ok(payload_len.div_ceil(stride))
    }

    /// Returns the exact byte offset in the blob where chunk `chunk_index` starts.
    pub fn chunk_offset(&self, chunk_index: u64) -> u64 {
        BLOB_PRELUDE_LEN as u64 + chunk_index * self.encrypted_stride()
    }
}

/// Derives the deterministic 24-byte XChaCha20 nonce for a specific chunk.
pub fn derive_chunk_nonce(
    base_nonce: &[u8; XNONCE_LEN],
    file_id: Uuid,
    chunk_index: u64,
    is_final: bool,
) -> [u8; XNONCE_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(CHUNK_NONCE_CONTEXT);
    hasher.update(base_nonce);
    hasher.update(file_id.as_bytes());
    hasher.update(&chunk_index.to_le_bytes());
    hasher.update(&[u8::from(is_final)]);

    let mut nonce = [0u8; XNONCE_LEN];
    hasher.finalize_xof().fill(&mut nonce);
    nonce
}

/// Builds the 33-byte Associated Authenticated Data (AAD) bound to each chunk.
pub fn build_chunk_aad(
    file_id: Uuid,
    chunk_index: u64,
    is_final: bool,
    plaintext_len: u32,
) -> [u8; CHUNK_AAD_LEN] {
    let mut aad = [0u8; CHUNK_AAD_LEN];
    aad[0..4].copy_from_slice(&BLOB_MAGIC);
    aad[4..20].copy_from_slice(file_id.as_bytes());
    aad[20..28].copy_from_slice(&chunk_index.to_le_bytes());
    aad[28] = u8::from(is_final);
    aad[29..33].copy_from_slice(&plaintext_len.to_le_bytes());
    aad
}

/// Encrypts a single plaintext chunk at `chunk_index` using XChaCha20-Poly1305.
pub fn encrypt_chunk(
    fek: &FileEncryptionKey,
    prelude: &BlobPrelude,
    chunk_index: u64,
    is_final: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > prelude.chunk_size as usize {
        return Err(CryptoError::InvalidChunkFormat(
            "plaintext exceeds configured chunk_size".to_string(),
        ));
    }
    if !is_final && plaintext.len() != prelude.chunk_size as usize {
        return Err(CryptoError::InvalidChunkFormat(
            "non-final chunk must match full chunk_size".to_string(),
        ));
    }

    let plaintext_len = u32::try_from(plaintext.len())
        .map_err(|_| CryptoError::InvalidChunkFormat("chunk length overflow".to_string()))?;

    let cipher = XChaCha20Poly1305::new_from_slice(fek.expose())
        .map_err(|_| CryptoError::InvalidChunkFormat("invalid FEK length".to_string()))?;

    let nonce_bytes =
        derive_chunk_nonce(&prelude.base_nonce, prelude.file_id, chunk_index, is_final);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = build_chunk_aad(prelude.file_id, chunk_index, is_final, plaintext_len);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Decrypts a single ciphertext chunk at `chunk_index` and verifies its AAD and Poly1305 tag.
pub fn decrypt_chunk(
    fek: &FileEncryptionKey,
    prelude: &BlobPrelude,
    chunk_index: u64,
    is_final: bool,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if ciphertext.len() < TAG_LEN {
        return Err(CryptoError::TruncatedStream);
    }
    let expected_plain_len = ciphertext.len() - TAG_LEN;
    if expected_plain_len > prelude.chunk_size as usize {
        return Err(CryptoError::InvalidChunkFormat(
            "ciphertext chunk exceeds configured chunk_size".to_string(),
        ));
    }
    if !is_final && expected_plain_len != prelude.chunk_size as usize {
        return Err(CryptoError::InvalidChunkFormat(
            "non-final ciphertext chunk has unexpected size".to_string(),
        ));
    }

    let plaintext_len = u32::try_from(expected_plain_len)
        .map_err(|_| CryptoError::InvalidChunkFormat("chunk length overflow".to_string()))?;

    let cipher = XChaCha20Poly1305::new_from_slice(fek.expose())
        .map_err(|_| CryptoError::InvalidChunkFormat("invalid FEK length".to_string()))?;

    let nonce_bytes =
        derive_chunk_nonce(&prelude.base_nonce, prelude.file_id, chunk_index, is_final);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let aad = build_chunk_aad(prelude.file_id, chunk_index, is_final, plaintext_len);

    let plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(Zeroizing::new(plain))
}

/// Encrypts an entire byte stream into `writer` using fixed-size chunks and returns the `BlobPrelude`.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    fek: &FileEncryptionKey,
    file_id: Uuid,
    chunk_size: usize,
) -> Result<BlobPrelude, CryptoError> {
    let chunk_size_u32 = u32::try_from(chunk_size)
        .map_err(|_| CryptoError::InvalidChunkFormat("chunk_size exceeds u32".to_string()))?;
    let prelude = BlobPrelude::new(file_id, chunk_size_u32)?;
    writer
        .write_all(&prelude.to_bytes())
        .map_err(|e| CryptoError::InvalidChunkFormat(e.to_string()))?;

    encrypt_stream_tail(reader, writer, fek, &prelude, 0)
}

fn encrypt_stream_tail<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    fek: &FileEncryptionKey,
    prelude: &BlobPrelude,
    mut chunk_index: u64,
) -> Result<BlobPrelude, CryptoError> {
    let chunk_size = prelude.chunk_size as usize;
    let mut buffer = Zeroizing::new(vec![0u8; chunk_size + 1]);
    let mut carry = 0usize;

    loop {
        let filled = carry
            + read_full_or_eof(reader, &mut buffer[carry..chunk_size])
                .map_err(|e| CryptoError::InvalidChunkFormat(e.to_string()))?;

        if filled < chunk_size {
            let encrypted = encrypt_chunk(fek, prelude, chunk_index, true, &buffer[..filled])?;
            writer
                .write_all(&encrypted)
                .map_err(|e| CryptoError::InvalidChunkFormat(e.to_string()))?;
            return Ok(*prelude);
        }

        let peeked = reader
            .read(&mut buffer[chunk_size..chunk_size + 1])
            .map_err(|e| CryptoError::InvalidChunkFormat(e.to_string()))?;
        if peeked == 0 {
            let encrypted = encrypt_chunk(fek, prelude, chunk_index, true, &buffer[..chunk_size])?;
            writer
                .write_all(&encrypted)
                .map_err(|e| CryptoError::InvalidChunkFormat(e.to_string()))?;
            return Ok(*prelude);
        }

        let encrypted = encrypt_chunk(fek, prelude, chunk_index, false, &buffer[..chunk_size])?;
        writer
            .write_all(&encrypted)
            .map_err(|e| CryptoError::InvalidChunkFormat(e.to_string()))?;
        chunk_index += 1;
        buffer[0] = buffer[chunk_size];
        carry = 1;
    }
}

/// Random-access reader over an encrypted chunked media blob supporting O(1) chunk decryption.
pub struct ChunkedBlobReader<R: Read + Seek> {
    reader: R,
    prelude: BlobPrelude,
    total_chunks: u64,
    blob_len: u64,
}

impl<R: Read + Seek> ChunkedBlobReader<R> {
    /// Opens an encrypted blob, validates its prelude, and computes chunk geometry in O(1).
    pub fn open(mut reader: R) -> Result<Self, CryptoError> {
        let blob_len = reader
            .seek(SeekFrom::End(0))
            .map_err(|e| CryptoError::InvalidChunkFormat(e.to_string()))?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| CryptoError::InvalidChunkFormat(e.to_string()))?;

        let mut prelude_buf = [0u8; BLOB_PRELUDE_LEN];
        reader
            .read_exact(&mut prelude_buf)
            .map_err(|_| CryptoError::TruncatedStream)?;

        let prelude = BlobPrelude::from_bytes(&prelude_buf)?;
        let total_chunks = prelude.total_chunks_from_blob_len(blob_len)?;

        Ok(Self {
            reader,
            prelude,
            total_chunks,
            blob_len,
        })
    }

    pub fn prelude(&self) -> &BlobPrelude {
        &self.prelude
    }

    pub fn total_chunks(&self) -> u64 {
        self.total_chunks
    }

    /// Decrypts a single chunk at `chunk_index` in O(1) without decrypting preceding chunks.
    pub fn decrypt_chunk_at(
        &mut self,
        fek: &FileEncryptionKey,
        chunk_index: u64,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if chunk_index >= self.total_chunks {
            return Err(CryptoError::ChunkIndexOutOfRange {
                expected: self.total_chunks,
                actual: chunk_index,
            });
        }

        let offset = self.prelude.chunk_offset(chunk_index);
        let is_final = chunk_index == self.total_chunks - 1;
        let expected_cipher_len = if is_final {
            usize::try_from(self.blob_len - offset).map_err(|_| {
                CryptoError::InvalidChunkFormat("final chunk size overflow".to_string())
            })?
        } else {
            usize::try_from(self.prelude.encrypted_stride())
                .map_err(|_| CryptoError::InvalidChunkFormat("stride overflow".to_string()))?
        };

        self.reader
            .seek(SeekFrom::Start(offset))
            .map_err(|e| CryptoError::InvalidChunkFormat(e.to_string()))?;

        let mut ciphertext = vec![0u8; expected_cipher_len];
        self.reader
            .read_exact(&mut ciphertext)
            .map_err(|_| CryptoError::TruncatedStream)?;

        decrypt_chunk(fek, &self.prelude, chunk_index, is_final, &ciphertext)
    }

    /// Verifies every chunk tag in the blob (used by Vault Scrub and post-import verification).
    pub fn verify_all_chunks(&mut self, fek: &FileEncryptionKey) -> Result<u64, CryptoError> {
        let mut total_plain_bytes = 0u64;
        for idx in 0..self.total_chunks {
            let plain = self.decrypt_chunk_at(fek, idx)?;
            total_plain_bytes += plain.len() as u64;
        }
        Ok(total_plain_bytes)
    }

    /// Decrypts the entire blob sequentially into `writer`.
    pub fn decrypt_all_to<W: Write>(
        &mut self,
        fek: &FileEncryptionKey,
        writer: &mut W,
    ) -> Result<u64, CryptoError> {
        let mut total_plain_bytes = 0u64;
        for idx in 0..self.total_chunks {
            let plain = self.decrypt_chunk_at(fek, idx)?;
            writer
                .write_all(&plain)
                .map_err(|e| CryptoError::InvalidChunkFormat(e.to_string()))?;
            total_plain_bytes += plain.len() as u64;
        }
        Ok(total_plain_bytes)
    }
}

fn read_full_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut read_so_far = 0;
    while read_so_far < buf.len() {
        match reader.read(&mut buf[read_so_far..])? {
            0 => break,
            n => read_so_far += n,
        }
    }
    Ok(read_so_far)
}
