use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use meshvault_crypto::{
    disable_core_dumps, unwrap_fek, Argon2Params, ChunkedBlobReader, MasterVaultKey, RecoveryKit,
    SecretString, VaultHeader, DEFAULT_CHUNK_SIZE, HEADER_FORMAT_VERSION, WRAPPED_FEK_LEN,
};
use meshvault_import::{
    strip_metadata_for_clean_export, DedupPolicy, ImportOptions, ImportPipeline,
};
use meshvault_storage::{atomic_write_file, FolderNode, VaultCatalog, VaultLayout};
use meshvault_sync::{
    export_verified_backup, DeviceNetworkState, LocalDirectoryRemote, SyncDownloadMode, SyncEngine,
    SyncPolicy,
};
use uuid::Uuid;

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1_700_000_000_000)
}

struct CliFlags {
    passphrase: Option<String>,
    folder: Option<String>,
    fast_test: bool,
    json: bool,
    clean: bool,
    on_demand: bool,
    positional: Vec<String>,
}

fn parse_flags(args: Vec<String>) -> CliFlags {
    let mut flags = CliFlags {
        passphrase: None,
        folder: None,
        fast_test: false,
        json: false,
        clean: false,
        on_demand: false,
        positional: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--passphrase" | "-p" if i + 1 < args.len() => {
                flags.passphrase = Some(args[i + 1].clone());
                i += 2;
            }
            "--folder" | "-f" if i + 1 < args.len() => {
                flags.folder = Some(args[i + 1].clone());
                i += 2;
            }
            "--fast-test" => {
                flags.fast_test = true;
                i += 1;
            }
            "--json" => {
                flags.json = true;
                i += 1;
            }
            "--clean" => {
                flags.clean = true;
                i += 1;
            }
            "--on-demand" => {
                flags.on_demand = true;
                i += 1;
            }
            other => {
                flags.positional.push(other.to_string());
                i += 1;
            }
        }
    }
    flags
}

fn unlock_vault(
    vault_dir: &Path,
    passphrase: &str,
) -> Result<(VaultLayout, VaultHeader, MasterVaultKey, VaultCatalog), String> {
    let layout = VaultLayout::new(vault_dir);
    let header = layout
        .load_header()
        .map_err(|e| format!("failed to load header: {e}"))?;
    let secret = SecretString::from(passphrase.to_string());
    let mvk = header
        .unlock_with_passphrase(&secret)
        .map_err(|e| format!("unlock failed: {e}"))?;
    let catalog = layout
        .load_catalog(&mvk)
        .map_err(|e| format!("failed to open catalog: {e}"))?;
    Ok((layout, header, mvk, catalog))
}

fn require_passphrase(flags: &CliFlags) -> Result<String, String> {
    flags
        .passphrase
        .clone()
        .or_else(|| env::var("MESHVAULT_PASSPHRASE").ok())
        .ok_or_else(|| "missing --passphrase <secret> (or MESHVAULT_PASSPHRASE env)".to_string())
}

fn require_vault_dir(flags: &CliFlags, usage: &str) -> Result<PathBuf, String> {
    flags
        .positional
        .first()
        .map(PathBuf::from)
        .ok_or_else(|| usage.to_string())
}

fn ensure_indexer_exclusions(vault_dir: &Path) -> Result<(), String> {
    atomic_write_file(&vault_dir.join(".nomedia"), b"")
        .map_err(|e| format!("failed to write .nomedia: {e}"))?;
    atomic_write_file(&vault_dir.join(".noindex"), b"")
        .map_err(|e| format!("failed to write .noindex: {e}"))?;
    Ok(())
}

fn run_cli() -> Result<(), String> {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let Some(cmd) = raw_args.first().map(String::as_str) else {
        print_help();
        return Ok(());
    };
    let flags = parse_flags(raw_args[1..].to_vec());

    match cmd {
        "version" | "--version" | "-V" => {
            println!(
                "meshvault {} (format v{}, chunk_size={} bytes)",
                env!("CARGO_PKG_VERSION"),
                HEADER_FORMAT_VERSION,
                DEFAULT_CHUNK_SIZE
            );
        }
        "info" => {
            let payload = serde_json::json!({
                "product": "MeshVault",
                "version": env!("CARGO_PKG_VERSION"),
                "format_version": HEADER_FORMAT_VERSION,
                "chunk_size_bytes": DEFAULT_CHUNK_SIZE,
                "cipher": "XChaCha20-Poly1305",
                "kdf": "Argon2id",
                "invariant": "zero-plaintext-on-disk"
            });
            println!("{payload}");
        }
        "init" => {
            let vault_dir =
                require_vault_dir(&flags, "usage: meshvault init <vault_dir> --passphrase <p>")?;
            let pass = require_passphrase(&flags)?;
            let params = if flags.fast_test {
                Argon2Params::fast_test()
            } else {
                Argon2Params::desktop_default()
            };
            let now = now_unix_ms();
            let secret = SecretString::from(pass);
            let (mut header, mvk) = VaultHeader::create_with_passphrase(&secret, params, now, 0)
                .map_err(|e| format!("create_with_passphrase failed: {e}"))?;
            let recovery = RecoveryKit::generate();
            header
                .add_recovery_slot(&mvk, &recovery)
                .map_err(|e| format!("add_recovery_slot failed: {e}"))?;

            let layout = VaultLayout::new(&vault_dir);
            layout
                .write_header_pair(&header)
                .map_err(|e| format!("write_header_pair failed: {e}"))?;
            let catalog = VaultCatalog::new(header.vault_id, now);
            layout
                .save_catalog(&mvk, &catalog)
                .map_err(|e| format!("save_catalog failed: {e}"))?;
            ensure_indexer_exclusions(&vault_dir)?;

            let mnemonic = recovery.to_mnemonic();
            if flags.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "initialized",
                        "vault_id": header.vault_id,
                        "vault_dir": vault_dir,
                        "recovery_words": mnemonic.as_str(),
                    })
                );
            } else {
                println!("Initialized vault {}", header.vault_id);
                println!("Recovery kit (24 words): {}", mnemonic.as_str());
            }
        }
        "status" => {
            let vault_dir = require_vault_dir(
                &flags,
                "usage: meshvault status <vault_dir> --passphrase <p>",
            )?;
            let pass = require_passphrase(&flags)?;
            let (_layout, header, _mvk, catalog) = unlock_vault(&vault_dir, &pass)?;
            let metrics = catalog.compute_metrics();
            println!(
                "{}",
                serde_json::json!({
                    "vault_id": header.vault_id,
                    "header_revision": header.revision,
                    "catalog_revision": catalog.catalog_revision,
                    "folder_count": metrics.folder_count,
                    "total_media": metrics.total_media,
                    "trashed_count": metrics.trashed_count,
                    "total_bytes": metrics.total_bytes,
                    "thumb_pack_bytes": metrics.thumb_pack_bytes,
                })
            );
        }
        "doctor" => {
            let vault_dir = require_vault_dir(
                &flags,
                "usage: meshvault doctor <vault_dir> --passphrase <p>",
            )?;
            let pass = require_passphrase(&flags)?;
            let (layout, _header, _mvk, catalog) = unlock_vault(&vault_dir, &pass)?;
            let report = layout.doctor_report(Some(&catalog));
            let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
            println!("{json}");
        }
        "import" => {
            if flags.positional.len() < 2 {
                return Err(
                    "usage: meshvault import <vault_dir> <source_path> --passphrase <p>"
                        .to_string(),
                );
            }
            let vault_dir = PathBuf::from(&flags.positional[0]);
            let source_path = PathBuf::from(&flags.positional[1]);
            let pass = require_passphrase(&flags)?;
            let (layout, _header, mvk, mut catalog) = unlock_vault(&vault_dir, &pass)?;
            let target_parent = catalog.root_folder_id;
            let now = now_unix_ms();

            if source_path.is_dir() {
                let options = ImportOptions::default();
                let report = ImportPipeline::run_directory_import(
                    &layout,
                    &mvk,
                    &mut catalog,
                    &source_path,
                    target_parent,
                    &options,
                    now,
                )
                .map_err(|e| format!("directory import failed: {e}"))?;
                layout
                    .save_catalog(&mvk, &catalog)
                    .map_err(|e| format!("save catalog failed: {e}"))?;
                let json = serde_json::to_string(&report).map_err(|e| e.to_string())?;
                println!("{json}");
            } else {
                let raw = fs::read(&source_path)
                    .map_err(|e| format!("failed to read {}: {e}", source_path.display()))?;
                let file_name = source_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("imported.bin");
                let segments: Vec<String> = flags
                    .folder
                    .as_deref()
                    .map(|f| vec![f.to_string()])
                    .unwrap_or_default();
                let res = ImportPipeline::import_bytes_item(
                    &layout,
                    &mvk,
                    &mut catalog,
                    target_parent,
                    &segments,
                    file_name,
                    &raw,
                    DedupPolicy::SkipDuplicate,
                    None,
                    now,
                )
                .map_err(|e| format!("file import failed: {e}"))?;
                layout
                    .save_catalog(&mvk, &catalog)
                    .map_err(|e| format!("save catalog failed: {e}"))?;
                println!(
                    "{}",
                    serde_json::json!({
                        "media_id": res.media_id,
                        "deduplicated_skip": res.deduplicated_skip,
                        "file_name": file_name,
                    })
                );
            }
        }
        "tree" => {
            let vault_dir =
                require_vault_dir(&flags, "usage: meshvault tree <vault_dir> --passphrase <p>")?;
            let pass = require_passphrase(&flags)?;
            let (_layout, _header, _mvk, catalog) = unlock_vault(&vault_dir, &pass)?;
            if flags.json {
                let folders: Vec<&FolderNode> = catalog.folders.values().collect();
                let json = serde_json::to_string(&folders).map_err(|e| e.to_string())?;
                println!("{json}");
            } else {
                for folder in catalog.folders.values() {
                    println!("{}  {}", folder.id, folder.name);
                }
            }
        }
        "ls" => {
            let vault_dir =
                require_vault_dir(&flags, "usage: meshvault ls <vault_dir> --passphrase <p>")?;
            let pass = require_passphrase(&flags)?;
            let (_layout, _header, _mvk, catalog) = unlock_vault(&vault_dir, &pass)?;
            let folder_id = match &flags.folder {
                Some(raw_id) => Uuid::parse_str(raw_id).map_err(|e| format!("bad uuid: {e}"))?,
                None => catalog.root_folder_id,
            };
            let (subfolders, media) = catalog.list_folder_contents(folder_id);
            if flags.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "folder_id": folder_id,
                        "subfolders": subfolders,
                        "media": media,
                    })
                );
            } else {
                for f in subfolders {
                    println!("[DIR]  {}  {}", f.id, f.name);
                }
                for m in media {
                    println!(
                        "[FILE] {}  {}  ({} B)",
                        m.id, m.original_name, m.plaintext_size
                    );
                }
            }
        }
        "search" => {
            if flags.positional.len() < 2 {
                return Err(
                    "usage: meshvault search <vault_dir> <query> --passphrase <p>".to_string(),
                );
            }
            let vault_dir = PathBuf::from(&flags.positional[0]);
            let query = &flags.positional[1];
            let pass = require_passphrase(&flags)?;
            let (_layout, _header, _mvk, catalog) = unlock_vault(&vault_dir, &pass)?;
            let matches = catalog.search_media(query);
            let json = serde_json::to_string(&matches).map_err(|e| e.to_string())?;
            println!("{json}");
        }
        "scrub" => {
            let vault_dir = require_vault_dir(
                &flags,
                "usage: meshvault scrub <vault_dir> --passphrase <p>",
            )?;
            let pass = require_passphrase(&flags)?;
            let (layout, _header, mvk, catalog) = unlock_vault(&vault_dir, &pass)?;
            let scrub = layout
                .scrub_vault(&mvk, &catalog)
                .map_err(|e| format!("scrub failed: {e}"))?;
            let json = serde_json::to_string(&scrub).map_err(|e| e.to_string())?;
            println!("{json}");
            if !scrub.corrupted_blobs.is_empty() || !scrub.missing_blobs.is_empty() {
                return Err("integrity errors detected during vault scrub".to_string());
            }
        }
        "export" => {
            if flags.positional.len() < 3 {
                return Err(
                    "usage: meshvault export <vault_dir> <media_id> <out_path> --passphrase <p>"
                        .to_string(),
                );
            }
            let vault_dir = PathBuf::from(&flags.positional[0]);
            let media_id = Uuid::parse_str(&flags.positional[1])
                .map_err(|e| format!("invalid media_id: {e}"))?;
            let out_path = PathBuf::from(&flags.positional[2]);
            let pass = require_passphrase(&flags)?;
            let (layout, _header, mvk, catalog) = unlock_vault(&vault_dir, &pass)?;
            let entry = catalog
                .media
                .get(&media_id)
                .ok_or_else(|| format!("media_id {media_id} not found"))?;
            let wrapped: [u8; WRAPPED_FEK_LEN] = entry
                .wrapped_fek
                .as_slice()
                .try_into()
                .map_err(|_| "corrupt wrapped FEK length".to_string())?;
            let fek = unwrap_fek(&mvk, media_id, &wrapped)
                .map_err(|e| format!("unwrap_fek failed: {e}"))?;
            let blob_file = fs::File::open(layout.blob_path(media_id))
                .map_err(|e| format!("open blob failed: {e}"))?;
            let mut reader =
                ChunkedBlobReader::open(blob_file).map_err(|e| format!("open reader: {e}"))?;
            let mut plain = Vec::with_capacity(entry.plaintext_size as usize);
            reader
                .decrypt_all_to(&fek, &mut plain)
                .map_err(|e| format!("decrypt failed: {e}"))?;

            let final_bytes = if flags.clean {
                strip_metadata_for_clean_export(&entry.mime_type, &plain)
            } else {
                plain
            };
            atomic_write_file(&out_path, &final_bytes)
                .map_err(|e| format!("write export failed: {e}"))?;
            println!(
                "{}",
                serde_json::json!({
                    "exported_media_id": media_id,
                    "out_path": out_path,
                    "clean_metadata_stripped": flags.clean,
                    "bytes_written": final_bytes.len(),
                })
            );
        }
        "backup" => {
            if flags.positional.len() < 2 {
                return Err(
                    "usage: meshvault backup <vault_dir> <dest_dir> --passphrase <p>".to_string(),
                );
            }
            let vault_dir = PathBuf::from(&flags.positional[0]);
            let dest_dir = PathBuf::from(&flags.positional[1]);
            let pass = require_passphrase(&flags)?;
            let (layout, _header, mvk, catalog) = unlock_vault(&vault_dir, &pass)?;
            let report = export_verified_backup(&layout, &mvk, &catalog, &dest_dir)
                .map_err(|e| format!("backup failed: {e}"))?;
            println!(
                "{}",
                serde_json::json!({
                    "copied_blobs": report.copied_blobs,
                    "copied_thumb_packs": report.copied_thumb_packs,
                    "scrub_checked_blobs": report.scrub.checked_blobs,
                    "scrub_corrupted": report.scrub.corrupted_blobs.len(),
                })
            );
        }
        "sync-local" => {
            if flags.positional.len() < 2 {
                return Err(
                    "usage: meshvault sync-local <vault_dir> <mirror_dir> --passphrase <p> [--on-demand]"
                        .to_string(),
                );
            }
            let vault_dir = PathBuf::from(&flags.positional[0]);
            let mirror_dir = PathBuf::from(&flags.positional[1]);
            let pass = require_passphrase(&flags)?;
            let (layout, _header, mvk, mut catalog) = unlock_vault(&vault_dir, &pass)?;
            let remote = LocalDirectoryRemote::new(&mirror_dir);
            let mut engine = SyncEngine::new(Uuid::new_v4(), 0);
            let mode = if flags.on_demand {
                SyncDownloadMode::MetadataAndThumbsOnly
            } else {
                SyncDownloadMode::FullMirror
            };
            let report = engine
                .sync_vault(
                    &layout,
                    &mvk,
                    &mut catalog,
                    &remote,
                    SyncPolicy::default(),
                    DeviceNetworkState::default(),
                    mode,
                    now_unix_ms(),
                )
                .map_err(|e| format!("sync failed: {e}"))?;
            println!(
                "{}",
                serde_json::json!({
                    "state": format!("{:?}", report.state),
                    "new_epoch": report.new_epoch,
                    "uploaded_blobs": report.uploaded_blobs,
                    "downloaded_blobs": report.downloaded_blobs,
                    "bytes_transferred": report.bytes_transferred,
                })
            );
        }
        "help" | "--help" | "-h" => {
            print_help();
        }
        other => {
            return Err(format!("unknown subcommand: {other}"));
        }
    }

    Ok(())
}

fn print_help() {
    println!(
        "MeshVault CLI v{} — Zero-Knowledge Vault & Recovery Tool\n\
         Subcommands: version, info, init, status, doctor, import, tree, ls, search, scrub, export, backup, sync-local",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() -> ExitCode {
    let _ = disable_core_dumps();
    match run_cli() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}
