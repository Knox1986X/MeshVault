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

    let root_contents = session.list_folder_contents(root_id).expect("list root");
    assert_eq!(root_contents.subfolders.len(), 1);
    let docs_contents = session
        .list_folder_contents(root_contents.subfolders[0].id.clone())
        .expect("list imported root");
    let nested_docs = session
        .list_folder_contents(docs_contents.subfolders[0].id.clone())
        .expect("list Docs");
    let year_contents = session
        .list_folder_contents(nested_docs.subfolders[0].id.clone())
        .expect("list 2026");
    assert_eq!(year_contents.media.len(), 1);

    let media_id = year_contents.media[0].id.clone();
    let decrypted_chunk = session
        .read_media_chunk(media_id.clone(), 0)
        .expect("chunk 0");
    assert_eq!(decrypted_chunk, b"%PDF-1.7-SAMPLE-DATA");

    let scrub = session.scrub_vault().expect("scrub");
    assert_eq!(scrub.checked_blobs, 1);
    assert_eq!(scrub.corrupted_count, 0);

    // Lock must zeroize MVK and reject any further decryption calls.
    session.lock();
    assert_eq!(session.security_state(), VaultSecurityState::Locked);
    assert!(matches!(
        session.read_media_chunk(media_id.clone(), 0),
        Err(FfiVaultError::VaultLocked)
    ));

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
            .read_media_all_bytes(media_id)
            .expect("read all"),
        b"%PDF-1.7-SAMPLE-DATA"
    );
}
