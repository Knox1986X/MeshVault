use std::fs;

use meshvault_crypto::{
    Argon2Params, ChunkedBlobReader, SecretString, VaultHeader, FLAG_SIZE_PADDING,
};
use meshvault_import::{DedupPolicy, ImportPipeline};
use meshvault_storage::{VaultCatalog, VaultLayout};
use meshvault_sync::{
    export_verified_backup, validate_app_folder_path, DeviceNetworkState, InMemoryMockRemote,
    LanPairingSession, LocalDirectoryRemote, PkceAuthFlow, RemoteSyncTransport, SyncDownloadMode,
    SyncEngine, SyncError, SyncPolicy, SyncState,
};
use tempfile::TempDir;
use uuid::Uuid;

fn create_test_vault(dir: &std::path::Path) -> (VaultLayout, meshvault_crypto::MasterVaultKey, VaultCatalog) {
    let layout = VaultLayout::new(dir);
    let pass = SecretString::from("sync-master-pass".to_string());
    let (header, mvk) = VaultHeader::create_with_passphrase(
        &pass,
        Argon2Params::fast_test(),
        1_700_000_000_000,
        FLAG_SIZE_PADDING,
    )
    .expect("header");
    layout.write_header_pair(&header).expect("write hdr");
    let catalog = VaultCatalog::new(header.vault_id, 1_700_000_000_000);
    layout.save_catalog(&mvk, &catalog).expect("save catalog");
    (layout, mvk, catalog)
}

#[test]
fn dropbox_app_folder_zero_knowledge_bidirectional_sync_and_conflicts() {
    let remote = InMemoryMockRemote::new();

    let dir_a = TempDir::new().expect("dir A");
    let (layout_a, mvk, mut cat_a) = create_test_vault(dir_a.path());
    let root_a = cat_a.root_folder_id;

    let secret_payload_a = b"SECRET_PHOTO_FROM_ANDROID_DEVICE_A";
    let res_a = ImportPipeline::import_bytes_item(
        &layout_a,
        &mvk,
        &mut cat_a,
        root_a,
        &["SecretPassports".to_string()],
        "passport_a.jpg",
        secret_payload_a,
        DedupPolicy::SkipDuplicate,
        None,
        1_700_000_001_000,
    )
    .expect("import A");

    let mut engine_a = SyncEngine::new(Uuid::new_v4(), 0);
    let policy = SyncPolicy {
        wifi_only: true,
        require_charging: false,
        min_battery_percent: 20,
        size_padding_bucket_bytes: 65_536,
    };

    // Metered network must pause without touching remote.
    let paused = engine_a
        .sync_vault(
            &layout_a,
            &mvk,
            &mut cat_a,
            &remote,
            policy,
            DeviceNetworkState {
                on_wifi: false,
                is_metered: true,
                is_charging: false,
                battery_percent: 80,
            },
            SyncDownloadMode::FullMirror,
            1_700_000_002_000,
        )
        .expect("paused check");
    assert_eq!(paused.state, SyncState::PausedMetered);
    assert_eq!(remote.snapshot_all_objects().len(), 0);

    // Full Wi-Fi sync from Device A uploads padded ciphertext under /MeshVault/.
    let report_a = engine_a
        .sync_vault(
            &layout_a,
            &mvk,
            &mut cat_a,
            &remote,
            policy,
            DeviceNetworkState::default(),
            SyncDownloadMode::FullMirror,
            1_700_000_003_000,
        )
        .expect("sync A");
    assert_eq!(report_a.state, SyncState::Synced);
    assert_eq!(report_a.uploaded_blobs, 1);

    // Zero-knowledge assertion: no plaintext folder/file names or bytes exist anywhere on Dropbox mock.
    let remote_objs = remote.snapshot_all_objects();
    assert!(!remote_objs.is_empty());
    for (path, bytes) in &remote_objs {
        assert!(path.starts_with("/MeshVault/"));
        assert!(!bytes
            .windows(b"SecretPassports".len())
            .any(|w| w == b"SecretPassports"));
        assert!(!bytes
            .windows(secret_payload_a.len())
            .any(|w| w == secret_payload_a));
        if path.ends_with(".mvb") {
            assert_eq!(bytes.len() % 65_536, 0);
        }
    }

    // Device B (CachyOS) joins with same vault_id & MVK, creates an offline edit before syncing -> conflict!
    let dir_b = TempDir::new().expect("dir B");
    let layout_b = VaultLayout::new(dir_b.path());
    layout_b
        .write_header_pair(&layout_a.load_header().expect("hdr"))
        .expect("write B hdr");
    let mut cat_b = VaultCatalog::new(cat_a.vault_id, 1_700_000_000_500);
    let root_b = cat_b.root_folder_id;
    let secret_payload_b = b"SECRET_SCAN_FROM_CACHYOS_DEVICE_B";
    let res_b = ImportPipeline::import_bytes_item(
        &layout_b,
        &mvk,
        &mut cat_b,
        root_b,
        &["DesktopScans".to_string()],
        "scan_b.pdf",
        secret_payload_b,
        DedupPolicy::SkipDuplicate,
        None,
        1_700_000_004_000,
    )
    .expect("import B");

    // Device B syncs in On-Demand mode first (metadata + thumbs only, no heavy `.mvb` downloads yet).
    let mut engine_b = SyncEngine::new(Uuid::new_v4(), 0);
    let report_b = engine_b
        .sync_vault(
            &layout_b,
            &mvk,
            &mut cat_b,
            &remote,
            policy,
            DeviceNetworkState::default(),
            SyncDownloadMode::MetadataAndThumbsOnly,
            1_700_000_005_000,
        )
        .expect("sync B conflict");
    assert_eq!(report_b.state, SyncState::ConflictResolved);
    assert!(report_b.merged_conflict);
    assert!(cat_b.media.contains_key(&res_a.media_id));
    assert!(cat_b.media.contains_key(&res_b.media_id));
    assert!(!layout_b.blob_path(res_a.media_id).exists());

    // Fetch Device A `.mvb` blob on demand and verify plaintext matches.
    engine_b
        .fetch_blob_on_demand(&layout_b, &mvk, cat_b.vault_id, res_a.media_id, &remote)
        .expect("on demand fetch");
    assert!(layout_b.blob_path(res_a.media_id).exists());

    let entry_a = cat_b.media.get(&res_a.media_id).expect("entry a");
    let wrapped: [u8; meshvault_crypto::WRAPPED_FEK_LEN] =
        entry_a.wrapped_fek.as_slice().try_into().unwrap();
    let fek = meshvault_crypto::unwrap_fek(&mvk, res_a.media_id, &wrapped).unwrap();
    let mut reader =
        ChunkedBlobReader::open(fs::File::open(layout_b.blob_path(res_a.media_id)).unwrap())
            .unwrap();
    let mut plain = Vec::new();
    reader.decrypt_all_to(&fek, &mut plain).unwrap();
    assert_eq!(plain, secret_payload_a);
}

#[test]
fn lan_qr_pairing_replay_protection_pkce_scope_and_usb_backup_scrub() {
    // 1. OAuth2 PKCE + /MeshVault/ scope guard
    let pkce = PkceAuthFlow::start("test-client-id", "meshvault://oauth");
    let url = pkce.build_authorize_url("csrf-token");
    assert!(url.contains("code_challenge_method=S256"));
    assert!(validate_app_folder_path("/MeshVault/vaults/abc/manifest.mvsm").is_ok());
    assert!(matches!(
        validate_app_folder_path("/Photos/outside.jpg"),
        Err(SyncError::ScopeViolation(_))
    ));
    assert!(matches!(
        validate_app_folder_path("/MeshVault/../escape"),
        Err(SyncError::ScopeViolation(_))
    ));

    // 2. Direct LAN pairing session + QR SAS verification + replay rejection
    let vault_id = Uuid::new_v4();
    let mut initiator = LanPairingSession::initiate(vault_id);
    let qr = initiator.to_qr_payload(Uuid::new_v4(), "192.168.1.42:9443");
    let mut peer = LanPairingSession::join_from_qr(&qr).expect("join qr");
    assert_eq!(initiator.verification_sas(), peer.verification_sas());

    let frame0 = initiator.seal_frame(b"SYNC_DELTA_EPOCH_2").expect("seal 0");
    let opened0 = peer.open_frame(&frame0).expect("open 0");
    assert_eq!(opened0, b"SYNC_DELTA_EPOCH_2");
    // Replaying frame 0 must fail sequence validation.
    assert!(matches!(
        peer.open_frame(&frame0),
        Err(SyncError::LanSequenceMismatch {
            expected: 1,
            actual: 0
        })
    ));

    // 3. LocalDirectoryRemote + Verified USB/Btrfs backup export with scrub
    let src_dir = TempDir::new().expect("src");
    let (layout, mvk, mut catalog) = create_test_vault(src_dir.path());
    let root = catalog.root_folder_id;
    ImportPipeline::import_bytes_item(
        &layout,
        &mvk,
        &mut catalog,
        root,
        &["BackupTest".to_string()],
        "doc.md",
        b"# Backup Verification",
        DedupPolicy::SkipDuplicate,
        None,
        1_700_000_010_000,
    )
    .expect("import");

    let usb_dir = TempDir::new().expect("usb");
    let backup_report =
        export_verified_backup(&layout, &mvk, &catalog, usb_dir.path()).expect("backup");
    assert_eq!(backup_report.copied_blobs, 1);
    assert_eq!(backup_report.scrub.checked_blobs, 1);
    assert!(backup_report.scrub.corrupted_blobs.is_empty());

    let local_remote_dir = TempDir::new().expect("local remote");
    let local_remote = LocalDirectoryRemote::new(local_remote_dir.path());
    local_remote
        .put_object("/MeshVault/ping.enc", b"cipher")
        .expect("put");
    assert_eq!(
        local_remote.get_object("/MeshVault/ping.enc").unwrap(),
        b"cipher"
    );
}
