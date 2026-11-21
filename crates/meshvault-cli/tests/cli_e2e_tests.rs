use std::fs;
use std::process::Command;

use tempfile::TempDir;

#[test]
fn cli_full_lifecycle_init_import_search_scrub_export_backup_and_sync() {
    let bin = env!("CARGO_BIN_EXE_meshvault");
    let root = TempDir::new().expect("tempdir");
    let vault_dir = root.path().join("vault");
    let src_dir = root.path().join("source_photos");
    let backup_dir = root.path().join("usb_backup");
    let mirror_dir = root.path().join("local_mirror");
    let exported_file = root.path().join("exported.txt");

    fs::create_dir_all(src_dir.join("2026/Moscow")).expect("mkdir");
    let secret_text = b"Confidential itinerary for Moscow trip";
    fs::write(src_dir.join("2026/Moscow/notes.txt"), secret_text).expect("write src");

    let pass = "cli-integration-secret";

    // 1. init --fast-test --json
    let out_init = Command::new(bin)
        .args([
            "init",
            vault_dir.to_str().unwrap(),
            "--passphrase",
            pass,
            "--fast-test",
            "--json",
        ])
        .output()
        .expect("run init");
    assert!(
        out_init.status.success(),
        "{}",
        String::from_utf8_lossy(&out_init.stderr)
    );
    let init_json: serde_json::Value = serde_json::from_slice(&out_init.stdout).expect("init json");
    assert_eq!(init_json["status"], "initialized");
    assert_eq!(
        init_json["recovery_words"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .count(),
        24
    );
    assert!(vault_dir.join(".nomedia").exists());
    assert!(vault_dir.join(".noindex").exists());

    // 2. import directory
    let out_import = Command::new(bin)
        .args([
            "import",
            vault_dir.to_str().unwrap(),
            src_dir.to_str().unwrap(),
            "--passphrase",
            pass,
        ])
        .output()
        .expect("run import");
    assert!(
        out_import.status.success(),
        "{}",
        String::from_utf8_lossy(&out_import.stderr)
    );
    let import_json: serde_json::Value =
        serde_json::from_slice(&out_import.stdout).expect("import json");
    assert_eq!(import_json["imported_files"], 1);

    // 3. status & doctor & tree & search
    let out_status = Command::new(bin)
        .args(["status", vault_dir.to_str().unwrap(), "--passphrase", pass])
        .output()
        .expect("status");
    assert!(out_status.status.success());
    let status_json: serde_json::Value = serde_json::from_slice(&out_status.stdout).unwrap();
    assert_eq!(status_json["total_media"], 1);

    let out_doctor = Command::new(bin)
        .args(["doctor", vault_dir.to_str().unwrap(), "--passphrase", pass])
        .output()
        .expect("doctor");
    assert!(out_doctor.status.success());

    let out_tree = Command::new(bin)
        .args([
            "tree",
            vault_dir.to_str().unwrap(),
            "--passphrase",
            pass,
            "--json",
        ])
        .output()
        .expect("tree");
    assert!(out_tree.status.success());

    let out_search = Command::new(bin)
        .args([
            "search",
            vault_dir.to_str().unwrap(),
            "notes",
            "--passphrase",
            pass,
        ])
        .output()
        .expect("search");
    assert!(out_search.status.success());
    let matches: Vec<serde_json::Value> = serde_json::from_slice(&out_search.stdout).unwrap();
    assert_eq!(matches.len(), 1);
    let media_id = matches[0]["id"].as_str().unwrap();

    // 4. scrub
    let out_scrub = Command::new(bin)
        .args(["scrub", vault_dir.to_str().unwrap(), "--passphrase", pass])
        .output()
        .expect("scrub");
    assert!(out_scrub.status.success());
    let scrub_json: serde_json::Value = serde_json::from_slice(&out_scrub.stdout).unwrap();
    assert_eq!(scrub_json["checked_blobs"], 1);

    // 5. export
    let out_export = Command::new(bin)
        .args([
            "export",
            vault_dir.to_str().unwrap(),
            media_id,
            exported_file.to_str().unwrap(),
            "--passphrase",
            pass,
        ])
        .output()
        .expect("export");
    assert!(
        out_export.status.success(),
        "{}",
        String::from_utf8_lossy(&out_export.stderr)
    );
    assert_eq!(fs::read(&exported_file).unwrap(), secret_text);

    // 6. backup & sync-local
    let out_backup = Command::new(bin)
        .args([
            "backup",
            vault_dir.to_str().unwrap(),
            backup_dir.to_str().unwrap(),
            "--passphrase",
            pass,
        ])
        .output()
        .expect("backup");
    assert!(out_backup.status.success());
    let backup_json: serde_json::Value = serde_json::from_slice(&out_backup.stdout).unwrap();
    assert_eq!(backup_json["copied_blobs"], 1);
    assert_eq!(backup_json["scrub_corrupted"], 0);

    let out_sync = Command::new(bin)
        .args([
            "sync-local",
            vault_dir.to_str().unwrap(),
            mirror_dir.to_str().unwrap(),
            "--passphrase",
            pass,
        ])
        .output()
        .expect("sync-local");
    assert!(out_sync.status.success());
    let sync_json: serde_json::Value = serde_json::from_slice(&out_sync.stdout).unwrap();
    assert_eq!(sync_json["uploaded_blobs"], 1);
}
