use std::io::Cursor;

use meshvault_crypto::{
    encrypt_stream, unwrap_fek, wrap_fek, Argon2Params, BlobPrelude, ChunkedBlobReader,
    CryptoError, FileEncryptionKey, KeyWrappingKey, MasterVaultKey, RecoveryKit, SecretString,
    VaultHeader, Zeroize, BLOB_PRELUDE_LEN, RECOVERY_WORD_COUNT, TAG_LEN,
};
use uuid::Uuid;

fn test_data(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i.wrapping_mul(31).wrapping_add(17)) & 0xFF) as u8)
        .collect()
}

#[test]
fn chunked_round_trip_and_random_access_out_of_order() {
    let fek = FileEncryptionKey::generate();
    let file_id = Uuid::new_v4();
    let chunk_size = 64usize;
    let plaintext = test_data(chunk_size * 4 + 19);

    let mut encrypted = Vec::new();
    let prelude = encrypt_stream(
        &mut Cursor::new(&plaintext),
        &mut encrypted,
        &fek,
        file_id,
        chunk_size,
    )
    .expect("stream encryption should succeed");

    assert_eq!(prelude.file_id, file_id);
    assert_eq!(prelude.chunk_size as usize, chunk_size);

    let mut reader = ChunkedBlobReader::open(Cursor::new(&encrypted)).expect("open blob");
    assert_eq!(reader.total_chunks(), 5);

    // Decrypt chunk 3 directly in O(1) without decrypting chunks 0, 1, or 2.
    let c3 = reader.decrypt_chunk_at(&fek, 3).expect("chunk 3");
    assert_eq!(&*c3, &plaintext[chunk_size * 3..chunk_size * 4]);

    // Decrypt final chunk 4 directly.
    let c4 = reader.decrypt_chunk_at(&fek, 4).expect("chunk 4");
    assert_eq!(&*c4, &plaintext[chunk_size * 4..]);

    // Decrypt chunk 0 directly.
    let c0 = reader.decrypt_chunk_at(&fek, 0).expect("chunk 0");
    assert_eq!(&*c0, &plaintext[0..chunk_size]);

    // Full sequential verification and decryption.
    let mut recovered = Vec::new();
    let total = reader
        .decrypt_all_to(&fek, &mut recovered)
        .expect("full decrypt");
    assert_eq!(total as usize, plaintext.len());
    assert_eq!(recovered, plaintext);
}

#[test]
fn empty_and_exact_boundary_streams_round_trip() {
    let fek = FileEncryptionKey::generate();
    let chunk_size = 128usize;

    // 0-byte file
    let mut enc_empty = Vec::new();
    encrypt_stream(
        &mut Cursor::new(Vec::<u8>::new()),
        &mut enc_empty,
        &fek,
        Uuid::new_v4(),
        chunk_size,
    )
    .expect("empty stream encrypt");
    let mut reader_empty = ChunkedBlobReader::open(Cursor::new(&enc_empty)).expect("open empty");
    assert_eq!(reader_empty.total_chunks(), 1);
    let mut out_empty = Vec::new();
    reader_empty
        .decrypt_all_to(&fek, &mut out_empty)
        .expect("decrypt empty");
    assert!(out_empty.is_empty());

    // Exact multiple of chunk_size (2 * 128 bytes)
    let exact = test_data(chunk_size * 2);
    let mut enc_exact = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&exact),
        &mut enc_exact,
        &fek,
        Uuid::new_v4(),
        chunk_size,
    )
    .expect("exact stream encrypt");
    let mut reader_exact = ChunkedBlobReader::open(Cursor::new(&enc_exact)).expect("open exact");
    assert_eq!(reader_exact.total_chunks(), 2);
    let mut out_exact = Vec::new();
    reader_exact
        .decrypt_all_to(&fek, &mut out_exact)
        .expect("decrypt exact");
    assert_eq!(out_exact, exact);
}

#[test]
fn tampering_any_byte_in_ciphertext_or_tag_fails() {
    let fek = FileEncryptionKey::generate();
    let file_id = Uuid::new_v4();
    let chunk_size = 128usize;
    let plaintext = test_data(300);

    let mut encrypted = Vec::new();
    encrypt_stream(
        &mut Cursor::new(&plaintext),
        &mut encrypted,
        &fek,
        file_id,
        chunk_size,
    )
    .expect("encrypt");

    // Flip one byte in chunk 1 ciphertext payload.
    let mut tampered_payload = encrypted.clone();
    let chunk1_start = BLOB_PRELUDE_LEN + chunk_size + TAG_LEN;
    tampered_payload[chunk1_start + 10] ^= 0x01;
    let mut reader = ChunkedBlobReader::open(Cursor::new(&tampered_payload)).expect("open");
    assert_eq!(
        reader.decrypt_chunk_at(&fek, 1).unwrap_err(),
        CryptoError::AuthenticationFailed
    );

    // Flip one byte in chunk 0 Poly1305 tag.
    let mut tampered_tag = encrypted.clone();
    tampered_tag[BLOB_PRELUDE_LEN + chunk_size + TAG_LEN - 1] ^= 0x80;
    let mut reader_tag = ChunkedBlobReader::open(Cursor::new(&tampered_tag)).expect("open");
    assert_eq!(
        reader_tag.verify_all_chunks(&fek).unwrap_err(),
        CryptoError::AuthenticationFailed
    );

    // Flip one byte in prelude file_id (changes AAD and nonce derivation).
    let mut tampered_prelude = encrypted;
    tampered_prelude[8] ^= 0x40;
    let mut reader_prelude = ChunkedBlobReader::open(Cursor::new(&tampered_prelude)).expect("open");
    assert_eq!(
        reader_prelude.decrypt_chunk_at(&fek, 0).unwrap_err(),
        CryptoError::AuthenticationFailed
    );
}

#[test]
fn swapping_two_chunks_fails_authentication() {
    let fek = FileEncryptionKey::generate();
    let file_id = Uuid::new_v4();
    let chunk_size = 64usize;
    let plaintext = test_data(chunk_size * 3 + 10);

    let mut encrypted = Vec::new();
    let prelude = encrypt_stream(
        &mut Cursor::new(&plaintext),
        &mut encrypted,
        &fek,
        file_id,
        chunk_size,
    )
    .expect("encrypt");

    let stride = prelude.encrypted_stride() as usize;
    let c0_start = BLOB_PRELUDE_LEN;
    let c1_start = BLOB_PRELUDE_LEN + stride;

    let mut swapped = encrypted;
    let (left, right) = swapped.split_at_mut(c1_start);
    left[c0_start..c0_start + stride].swap_with_slice(&mut right[..stride]);

    let mut reader = ChunkedBlobReader::open(Cursor::new(&swapped)).expect("open");
    assert_eq!(
        reader.decrypt_chunk_at(&fek, 0).unwrap_err(),
        CryptoError::AuthenticationFailed
    );
    assert_eq!(
        reader.decrypt_chunk_at(&fek, 1).unwrap_err(),
        CryptoError::AuthenticationFailed
    );
    assert_eq!(
        reader.verify_all_chunks(&fek).unwrap_err(),
        CryptoError::AuthenticationFailed
    );
}

#[test]
fn truncating_final_chunk_or_removing_last_chunk_fails() {
    let fek = FileEncryptionKey::generate();
    let file_id = Uuid::new_v4();
    let chunk_size = 64usize;
    let plaintext = test_data(chunk_size * 2 + 25);

    let mut encrypted = Vec::new();
    let prelude = encrypt_stream(
        &mut Cursor::new(&plaintext),
        &mut encrypted,
        &fek,
        file_id,
        chunk_size,
    )
    .expect("encrypt");

    // Case 1: chop 5 bytes off the end of the final chunk.
    let mut truncated_tail = encrypted.clone();
    truncated_tail.truncate(truncated_tail.len() - 5);
    let mut reader1 = ChunkedBlobReader::open(Cursor::new(&truncated_tail)).expect("open");
    assert_eq!(
        reader1.verify_all_chunks(&fek).unwrap_err(),
        CryptoError::AuthenticationFailed
    );

    // Case 2: remove the entire final chunk (chunk 2) so chunk 1 looks like the end.
    let mut dropped_last_chunk = encrypted.clone();
    let two_chunks_len = BLOB_PRELUDE_LEN + (prelude.encrypted_stride() as usize) * 2;
    dropped_last_chunk.truncate(two_chunks_len);
    let mut reader2 = ChunkedBlobReader::open(Cursor::new(&dropped_last_chunk)).expect("open");
    assert_eq!(reader2.total_chunks(), 2);
    // Chunk 1 was encrypted with is_final = false, so authenticating it as final fails!
    assert_eq!(
        reader2.decrypt_chunk_at(&fek, 1).unwrap_err(),
        CryptoError::AuthenticationFailed
    );

    // Case 3: truncate into prelude / missing all chunks.
    let mut header_only = encrypted;
    header_only.truncate(BLOB_PRELUDE_LEN);
    assert!(matches!(
        ChunkedBlobReader::open(Cursor::new(&header_only)),
        Err(CryptoError::TruncatedStream)
    ));
}

#[test]
fn header_argon2id_mvk_wrap_rotation_and_fek_isolation() {
    let pass1 = SecretString::from("correct-horse-battery-staple-2026".to_string());
    let pass2 = SecretString::from("rotated-strong-passphrase-99".to_string());
    let wrong_pass = SecretString::from("wrong-passphrase".to_string());

    let (mut header, mvk) = VaultHeader::create_with_passphrase(
        &pass1,
        Argon2Params::fast_test(),
        1_700_000_000_000,
        0,
    )
    .expect("create vault header");

    // Wrap a file FEK using the MVK.
    let file_id = Uuid::new_v4();
    let fek = FileEncryptionKey::generate();
    let wrapped_fek = wrap_fek(&mvk, file_id, &fek).expect("wrap fek");

    // Wrong passphrase must fail.
    assert_eq!(
        header.unlock_with_passphrase(&wrong_pass).unwrap_err(),
        CryptoError::SlotNotFound
    );

    // Rotate passphrase without re-encrypting any media blobs or FEKs.
    header
        .rotate_passphrase(&pass1, &pass2, None)
        .expect("rotate passphrase");
    assert_eq!(header.revision, 2);

    // Old passphrase no longer works.
    assert_eq!(
        header.unlock_with_passphrase(&pass1).unwrap_err(),
        CryptoError::SlotNotFound
    );

    // Serialize and deserialize header, unlock with new passphrase, and unwrap FEK.
    let encoded = header.to_bytes().expect("serialize header");
    let decoded = VaultHeader::from_bytes(&encoded).expect("deserialize header");
    let unlocked_mvk = decoded
        .unlock_with_passphrase(&pass2)
        .expect("unlock with rotated passphrase");

    assert_eq!(unlocked_mvk.expose(), mvk.expose());
    let unwrapped_fek = unwrap_fek(&unlocked_mvk, file_id, &wrapped_fek).expect("unwrap fek");
    assert_eq!(unwrapped_fek.expose(), fek.expose());

    // Keyed deduplication hash is deterministic for the same MVK and differs for another MVK.
    let other_mvk = MasterVaultKey::generate();
    assert_eq!(
        mvk.keyed_dedup_hash(b"sample-photo-bytes"),
        unlocked_mvk.keyed_dedup_hash(b"sample-photo-bytes")
    );
    assert_ne!(
        mvk.keyed_dedup_hash(b"sample-photo-bytes"),
        other_mvk.keyed_dedup_hash(b"sample-photo-bytes")
    );
}

#[test]
fn recovery_kit_24_words_checksum_and_mvk_recovery() {
    let pass = SecretString::from("vault-master-secret".to_string());
    let (mut header, mvk) =
        VaultHeader::create_with_passphrase(&pass, Argon2Params::fast_test(), 1_700_000_000_000, 0)
            .expect("create header");

    let kit = RecoveryKit::generate();
    let phrase = kit.to_mnemonic();
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), RECOVERY_WORD_COUNT);

    header
        .add_recovery_slot(&mvk, &kit)
        .expect("add recovery slot");

    // Mutate one word to verify checksum or dictionary rejection.
    let mut bad_words = words.clone();
    bad_words[0] = if bad_words[0] == "abandon" {
        "ability"
    } else {
        "abandon"
    };
    let bad_phrase = bad_words.join(" ");
    assert!(matches!(
        RecoveryKit::from_mnemonic(&bad_phrase),
        Err(CryptoError::InvalidRecoveryMnemonic(_))
    ));

    // Recover using valid 24-word mnemonic.
    let parsed_kit = RecoveryKit::from_mnemonic(&phrase).expect("parse valid mnemonic");
    let recovered_mvk = header
        .unlock_with_recovery_kit(&parsed_kit)
        .expect("unlock via recovery kit");
    assert_eq!(recovered_mvk.expose(), mvk.expose());

    // Also verify hardware slot wrapping/unwrapping.
    let hw_kek = KeyWrappingKey::generate();
    let hw_slot_id = header
        .add_hardware_slot(&mvk, &hw_kek)
        .expect("add hardware slot");
    let hw_mvk = header
        .unlock_with_wrapping_key(hw_slot_id, &hw_kek)
        .expect("unlock via hardware slot");
    assert_eq!(hw_mvk.expose(), mvk.expose());
}

#[test]
fn dual_header_recovers_from_corrupted_primary_or_stale_backup() {
    let pass = SecretString::from("dual-header-pass".to_string());
    let (mut header, mvk) =
        VaultHeader::create_with_passphrase(&pass, Argon2Params::fast_test(), 1_700_000_000_000, 0)
            .expect("create");
    let rev1_bytes = header.to_bytes().expect("rev1 bytes");

    let kit = RecoveryKit::generate();
    header.add_recovery_slot(&mvk, &kit).expect("rev2");
    let rev2_bytes = header.to_bytes().expect("rev2 bytes");

    // Newer backup wins over older primary.
    let chosen = VaultHeader::select_latest_valid(Some(&rev1_bytes), Some(&rev2_bytes))
        .expect("select latest");
    assert_eq!(chosen.revision, 2);

    // Corrupted primary falls back cleanly to backup.
    let mut corrupted = rev2_bytes.clone();
    corrupted[10] ^= 0xFF;
    let recovered =
        VaultHeader::select_latest_valid(Some(&corrupted), Some(&rev1_bytes)).expect("fallback");
    assert_eq!(recovered.revision, 1);

    // Verify BlobPrelude round-trip.
    let prelude = BlobPrelude::new(Uuid::new_v4(), 1024 * 1024).expect("prelude");
    let parsed = BlobPrelude::from_bytes(&prelude.to_bytes()).expect("parse prelude");
    assert_eq!(prelude, parsed);
}

#[test]
fn explicit_zeroize_wipes_sensitive_key_buffers() {
    let mut raw = [0xA5u8; 32];
    raw.zeroize();
    assert_eq!(raw, [0u8; 32]);

    let mut mvk = MasterVaultKey::from_bytes([0x5Au8; 32]);
    assert_ne!(mvk.expose(), &[0u8; 32]);
    mvk.zeroize();
    assert_eq!(mvk.expose(), &[0u8; 32]);
}
