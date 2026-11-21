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

#[test]
fn ffi_stage4_decoy_trash_clean_export_and_doctor() {
    let vault_tmp = TempDir::new().expect("vault dir");
    let vault_path = vault_tmp.path().to_string_lossy().to_string();
    let session = MeshVaultSession::create_new(
        vault_path.clone(),
        "real-pass".to_string(),
        1_700_000_000_000,
        true,
    )
    .expect("create");

    // Configure Decoy Vault with independent MVK and separate catalog.
    session
        .configure_decoy_vault("decoy-pin".to_string(), 1_700_000_000_100)
        .expect("decoy");

    // Build a minimal JPEG with APP1 EXIF camera "SecretCam".
    let exif_tiff = {
        let mut t = Vec::new();
        t.extend_from_slice(b"MM\x00\x2A");
        t.extend_from_slice(&8u32.to_be_bytes());
        t.extend_from_slice(&1u16.to_be_bytes());
        // Tag 0x0110 (Model), ASCII (2), count 10, offset 26
        t.extend_from_slice(&0x0110u16.to_be_bytes());
        t.extend_from_slice(&2u16.to_be_bytes());
        t.extend_from_slice(&10u32.to_be_bytes());
        t.extend_from_slice(&26u32.to_be_bytes());
        t.extend_from_slice(&0u32.to_be_bytes());
        t.extend_from_slice(b"SecretCam\0");
        t
    };
    let mut app1_payload = b"Exif\0\0".to_vec();
    app1_payload.extend_from_slice(&exif_tiff);
    let app1_len = (app1_payload.len() + 2) as u16;
    let mut sample_jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1];
    sample_jpeg.extend_from_slice(&app1_len.to_be_bytes());
    sample_jpeg.extend_from_slice(&app1_payload);
    sample_jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
    sample_jpeg.extend_from_slice(&[0xFF, 0xD9]);

    let root = session.root_folder_id().expect("root");
    let imported = session
        .import_bytes_item(
            root.clone(),
            vec!["Private".to_string()],
            "camera.jpg".to_string(),
            sample_jpeg,
            FfiDedupPolicy::SkipDuplicate,
            None,
            1_700_000_001_000,
        )
        .expect("import jpeg");

    // Verify Clean Export strips APP1 EXIF segment in RAM.
    let cleaned = session
        .clean_export_media_bytes(imported.media_id.clone())
        .expect("clean export");
    assert!(meshvault_import::parse_jpeg_exif(&cleaned).camera.is_none());

    // Tagging, date edit, slideshow traversal, Safe Presentation, and Doctor report.
    session
        .update_media_tags_and_note(
            imported.media_id.clone(),
            vec!["travel".to_string()],
            Some("Border crossing scan".to_string()),
        )
        .expect("update tags");
    session
        .update_media_captured_at(imported.media_id.clone(), Some(1_712_000_000_000))
        .expect("update captured_at");
    assert_eq!(
        session
            .collect_slideshow_media(root, true)
            .expect("slideshow")
            .len(),
        1
    );
    assert_eq!(session.search_media("border".to_string()).unwrap().len(), 1);

    session.enter_safe_presentation().expect("enter safe");
    assert_eq!(
        session.security_state(),
        VaultSecurityState::UnlockedSafePresentation
    );
    session.exit_safe_presentation().expect("exit safe");
    assert_eq!(session.security_state(), VaultSecurityState::UnlockedFull);

    let doctor = session.doctor_report().expect("doctor");
    assert!(doctor.primary_header_valid);
    assert!(doctor.backup_header_valid);
    assert!(doctor.decoy_configured);
    assert_eq!(doctor.media_count, 1);

    // Move to Trash -> list -> restore -> move again -> shred after 31 days.
    session
        .move_to_trash(imported.media_id.clone(), 1_700_000_100_000)
        .expect("trash");
    assert_eq!(session.list_trashed_media().unwrap().len(), 1);
    session
        .restore_from_trash(imported.media_id.clone())
        .expect("restore");
    assert_eq!(session.list_trashed_media().unwrap().len(), 0);
    session
        .move_to_trash(imported.media_id, 1_700_000_100_000)
        .expect("trash again");
    let purged = session
        .purge_expired_trash(30, 1_700_000_100_000 + 31 * 86_400_000)
        .expect("purge");
    assert_eq!(purged, 1);

    session.lock();

    // Unlocking with decoy passphrase opens an empty Decoy catalog without seeing real folders.
    let decoy = MeshVaultSession::unlock_with_passphrase(vault_path, "decoy-pin".to_string())
        .expect("unlock decoy");
    assert_eq!(decoy.security_state(), VaultSecurityState::UnlockedDecoy);
    assert_eq!(decoy.vault_metrics().unwrap().total_media, 0);
    assert_eq!(decoy.list_all_media_timeline().unwrap().len(), 0);
}
