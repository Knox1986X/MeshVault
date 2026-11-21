use std::fs;

use meshvault_ffi::{FfiDedupPolicy, FfiVaultError, MeshVaultSession, VaultSecurityState};
use tempfile::TempDir;

#[test]
fn ffi_session_lifecycle_import_read_lock_and_recovery() {
    let vault_tmp = TempDir::new().expect("vault dir");
    let src_tmp = TempDir::new().expect("source dir");
    let sub = src_tmp.path().join("Docs").join("2026");
    fs::create_dir_all(&sub).expect("mkdir");
    fs::write(sub.join("contract.pdf"), b"%PDF-1.7-SAMPLE-DATA").expect("write pdf");

    let vault_path = vault_tmp.path().to_string_lossy().to_string();
    let session = MeshVaultSession::create_new(
        vault_path.clone(),
        "ffi-pass-1".to_string(),
        1_700_000_000_000,
        true,
    )
    .expect("create session");

    assert_eq!(session.security_state(), VaultSecurityState::UnlockedFull);
    let recovery_phrase = session
        .add_recovery_kit_slot()
        .expect("add recovery kit slot");

    let hw_key = vec![0x42u8; 32];
    let hw_slot_id = session
        .add_hardware_keystore_slot(hw_key.clone())
        .expect("add hardware keystore slot");

    let root_id = session.root_folder_id().expect("root id");
    let report = session
        .import_directory(
            src_tmp.path().to_string_lossy().to_string(),
            root_id.clone(),
            FfiDedupPolicy::SkipDuplicate,
            1_700_000_001_000,
        )
        .expect("import via ffi");
    assert_eq!(report.imported_files, 1);

    // Also import an in-memory SAF stream item into nested subfolder.
    let saf_res = session
        .import_bytes_item(
            root_id.clone(),
            vec!["AndroidSAF".to_string(), "Receipts".to_string()],
            "ticket.md".to_string(),
            b"# Flight Ticket".to_vec(),
            FfiDedupPolicy::SkipDuplicate,
            Some(1_700_000_001_500),
            1_700_000_001_600,
        )
        .expect("import bytes item");
    assert_eq!(saf_res.bytes_encrypted, 15);

    let breadcrumbs = session
        .get_folder_breadcrumbs(saf_res.target_folder_id.clone())
        .expect("breadcrumbs");
    assert_eq!(breadcrumbs.len(), 3);
    assert_eq!(breadcrumbs[2].name, "Receipts");

    let metrics = session.vault_metrics().expect("metrics");
    assert_eq!(metrics.total_media, 2);
    assert_eq!(metrics.doc_count, 2);

    let root_contents = session.list_folder_contents(root_id).expect("list root");
    assert_eq!(root_contents.subfolders.len(), 2);

    let timeline = session.list_all_media_timeline().expect("timeline");
    assert_eq!(timeline.len(), 2);

    let first_media_id = timeline[0].id.clone();
    assert!(session.toggle_favorite(first_media_id).expect("fav"));

    let scrub = session.scrub_vault().expect("scrub");
    assert_eq!(scrub.checked_blobs, 2);
    assert_eq!(scrub.corrupted_count, 0);

    // Lock must zeroize MVK and reject any further decryption calls.
    session.lock();
    assert_eq!(session.security_state(), VaultSecurityState::Locked);
    assert!(matches!(
        session.read_media_chunk(saf_res.media_id.clone(), 0),
        Err(FfiVaultError::VaultLocked)
    ));

    // Unlock using Hardware Keystore wrapping key slot.
    let hw_session =
        MeshVaultSession::unlock_with_hardware_key(vault_path.clone(), hw_slot_id, hw_key)
            .expect("unlock via hardware slot");
    assert_eq!(
        hw_session
            .read_media_chunk(saf_res.media_id.clone(), 0)
            .expect("chunk 0"),
        b"# Flight Ticket"
    );
    hw_session.lock();

    // Re-unlock using 24-word Recovery Kit and rotate passphrase.
    let recovered = MeshVaultSession::unlock_with_recovery_kit(vault_path.clone(), recovery_phrase)
        .expect("unlock via recovery kit");
    recovered
        .rotate_passphrase("ffi-pass-1".to_string(), "ffi-pass-2".to_string())
        .expect("rotate passphrase");
    recovered.lock();

    let unlocked_new =
        MeshVaultSession::unlock_with_passphrase(vault_path, "ffi-pass-2".to_string())
            .expect("unlock with rotated pass");
    assert_eq!(
        unlocked_new
            .read_media_all_bytes(saf_res.media_id)
            .expect("read all"),
        b"# Flight Ticket"
    );
}
