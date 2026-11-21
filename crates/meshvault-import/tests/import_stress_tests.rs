use std::fs;
use std::io::Cursor;

use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
use meshvault_crypto::{Argon2Params, MasterVaultKey, SecretString, VaultHeader};
use meshvault_import::{
    generate_synthetic_tree, parse_jpeg_exif, scan_directory_tree, DedupPolicy, ImportError,
    ImportOptions, ImportPipeline, ImportState, ScanOptions,
};
use meshvault_storage::{VaultCatalog, VaultLayout};
use tempfile::TempDir;

#[test]
fn stress_test_5000_objects_recursive_import_with_simulated_crash_and_wal_resume() {
    let source_tmp = TempDir::new().expect("create source tempdir");
    let vault_tmp = TempDir::new().expect("create vault tempdir");

    // 50 * 10 * 10 = 5000 nested objects across 3+ subfolder levels.
    let created = generate_synthetic_tree(source_tmp.path(), 50, 10, 10).expect("generate 5000");
    assert_eq!(created, 5_000);

    let pass = SecretString::from("stress-test-passphrase".to_string());
    let (header, mvk) =
        VaultHeader::create_with_passphrase(&pass, Argon2Params::fast_test(), 1_700_000_000_000, 0)
            .expect("create header");

    let layout = VaultLayout::new(vault_tmp.path());
    layout.write_header_pair(&header).expect("write headers");

    let mut catalog = VaultCatalog::new(header.vault_id, 1_700_000_000_000);
    layout.save_catalog(&mvk, &catalog).expect("save catalog");

    let crash_options = ImportOptions {
        dedup_policy: DedupPolicy::SkipDuplicate,
        chunk_size: 64 * 1024,
        generate_thumbnails: false,
        checkpoint_every: 250,
        scan_options: ScanOptions::default(),
        selected_relative_folders: None,
        max_items_before_simulated_crash: Some(2_345),
    };

    let root_id = catalog.root_folder_id;
    let err = ImportPipeline::run_directory_import(
        &layout,
        &mvk,
        &mut catalog,
        source_tmp.path(),
        root_id,
        &crash_options,
        1_700_000_001_000,
    )
    .expect_err("simulated crash must interrupt import at 2345 items");

    assert!(matches!(
        err,
        ImportError::SimulatedCrash { processed: 2_345 }
    ));

    // Verify WAL exists on disk and contains zero plaintext filenames or folder names.
    let wal_bytes = fs::read(layout.import_wal_path()).expect("wal exists after crash");
    assert!(!wal_bytes.windows(8).any(|w| w == b"trip_000"));
    assert!(!wal_bytes.windows(11).any(|w| w == b"camera_roll"));

    // Simulate clean process restart: reload header, unlock MVK, reload catalog from disk.
    let reloaded_header = layout.load_header().expect("reload header");
    let unlocked_mvk: MasterVaultKey = reloaded_header
        .unlock_with_passphrase(&pass)
        .expect("unlock after restart");
    let mut reloaded_catalog = layout.load_catalog(&unlocked_mvk).expect("reload catalog");

    let resumed = ImportPipeline::resume_from_wal(
        &layout,
        &unlocked_mvk,
        &mut reloaded_catalog,
        None,
        1_700_000_002_000,
    )
    .expect("resume from WAL should complete all 5000 items");

    assert!(resumed.resumed_from_wal);
    assert_eq!(resumed.final_state, ImportState::Completed);
    assert_eq!(reloaded_catalog.media.len(), 5_000);
    assert!(!layout.import_wal_path().exists());

    // Verify nested folder hierarchy preserved (root + source dir + 50 branches + 500 days + 500 camera_roll).
    let root_name = source_tmp
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let imported_root_id = reloaded_catalog
        .find_child_folder(reloaded_catalog.root_folder_id, &root_name)
        .expect("imported root folder");
    let trip_049 = reloaded_catalog
        .find_child_folder(imported_root_id, "trip_049")
        .expect("trip_049");
    let day_09 = reloaded_catalog
        .find_child_folder(trip_049, "day_09")
        .expect("day_09");
    let camera_roll = reloaded_catalog
        .find_child_folder(day_09, "camera_roll")
        .expect("camera_roll");
    let (_, leaf_items) = reloaded_catalog.list_folder_contents(camera_roll);
    assert_eq!(leaf_items.len(), 10);

    // Verify every single encrypted chunk across all 5000 blobs.
    let scrub = layout
        .scrub_vault(&unlocked_mvk, &reloaded_catalog)
        .expect("scrub vault");
    assert_eq!(scrub.checked_blobs, 5_000);
    assert_eq!(scrub.checked_chunks, 5_000);
    assert!(scrub.corrupted_blobs.is_empty());
    assert!(scrub.missing_blobs.is_empty());
}

#[test]
fn real_image_thumbnail_pack_dedup_quarantine_and_incremental_merge() {
    let source_tmp = TempDir::new().expect("source dir");
    let vault_tmp = TempDir::new().expect("vault dir");
    let album_dir = source_tmp.path().join("AlpsTrip").join("Day1");
    fs::create_dir_all(&album_dir).expect("mkdir");

    // Write a valid 128x128 PNG image.
    let mut img = RgbaImage::new(128, 128);
    for (x, y, px) in img.enumerate_pixels_mut() {
        *px = Rgba([(x * 2) as u8, (y * 2) as u8, ((x + y) % 255) as u8, 255]);
    }
    let mut png_bytes = Vec::new();
    DynamicImage::ImageRgba8(img)
        .write_to(&mut Cursor::new(&mut png_bytes), ImageFormat::Png)
        .expect("encode png");
    fs::write(album_dir.join("glacier_view.png"), &png_bytes).expect("write png");

    // Write a 0-byte corrupted file that must go to quarantine without aborting import.
    fs::write(album_dir.join("broken_empty.jpg"), b"").expect("write empty");

    let pass = SecretString::from("media-vault-pass".to_string());
    let (header, mvk) =
        VaultHeader::create_with_passphrase(&pass, Argon2Params::fast_test(), 1_700_000_000_000, 0)
            .expect("header");
    let layout = VaultLayout::new(vault_tmp.path());
    layout.write_header_pair(&header).expect("write header");
    let mut catalog = VaultCatalog::new(header.vault_id, 1_700_000_000_000);

    let preview = scan_directory_tree(source_tmp.path(), &ScanOptions::default()).expect("scan");
    assert_eq!(preview.counts.photos, 2);

    let root_id = catalog.root_folder_id;
    let report = ImportPipeline::run_directory_import(
        &layout,
        &mvk,
        &mut catalog,
        source_tmp.path(),
        root_id,
        &ImportOptions::default(),
        1_700_000_001_000,
    )
    .expect("import with quarantine");

    assert_eq!(report.imported_files, 1);
    assert_eq!(report.quarantined_files.len(), 1);
    assert!(report.quarantined_files[0]
        .source_path
        .ends_with("broken_empty.jpg"));

    let entry = catalog.media.values().next().expect("one imported png");
    assert_eq!(entry.width, Some(128));
    assert_eq!(entry.height, Some(128));
    assert!(entry.phash.is_some());
    assert!(entry.micro_thumb.is_some());
    let locator = entry.thumb.expect("thumb locator in 4 MiB pack");

    let decrypted_thumb = layout
        .read_thumbnail(&mvk, &catalog, entry.id, locator)
        .expect("decrypt thumbnail in RAM");
    assert!(!decrypted_thumb.is_empty());

    // Re-importing the exact same tree with SkipDuplicate performs Incremental Folder Merge.
    let merge_report = ImportPipeline::run_directory_import(
        &layout,
        &mvk,
        &mut catalog,
        source_tmp.path(),
        root_id,
        &ImportOptions::default(),
        1_700_000_002_000,
    )
    .expect("incremental merge");
    assert_eq!(merge_report.imported_files, 0);
    assert_eq!(merge_report.skipped_duplicates, 1);
    assert_eq!(catalog.media.len(), 1);

    // Importing into a different parent with LinkIntoTargetFolder reuses blob without duplicating .mvb.
    let second_parent = catalog
        .create_folder(catalog.root_folder_id, "FavoritesCopy", 1_700_000_003_000)
        .expect("second parent");
    let link_opts = ImportOptions {
        dedup_policy: DedupPolicy::LinkIntoTargetFolder,
        ..ImportOptions::default()
    };
    let link_report = ImportPipeline::run_directory_import(
        &layout,
        &mvk,
        &mut catalog,
        source_tmp.path(),
        second_parent,
        &link_opts,
        1_700_000_004_000,
    )
    .expect("link dedup");
    assert_eq!(link_report.linked_duplicates, 1);
    assert_eq!(catalog.media.len(), 1);
}

#[test]
fn jpeg_exif_parser_extracts_camera_and_datetime_without_disk_writes() {
    // Minimal synthetic JPEG SOI + APP1 EXIF (little-endian TIFF) + EOI.
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II"); // Little endian
    tiff.extend_from_slice(&42u16.to_le_bytes());
    tiff.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at offset 8

    // IFD0: 3 entries (Make, Model, ExifIFD) -> 2 + 3*12 + 4 = 42 bytes -> data starts at 8 + 42 = 50.
    let make_bytes = b"Fujifilm\0";
    let model_bytes = b"X-T5\0";
    let dt_bytes = b"2026:07:15 14:30:00\0";

    let make_off = 50u32;
    let model_off = make_off + make_bytes.len() as u32;
    let exif_ifd_off = model_off + model_bytes.len() as u32;
    // ExifIFD has 1 entry (2 + 12 + 4 = 18 bytes), DateTimeOriginal string follows it.
    let dt_off = exif_ifd_off + 18;

    tiff.extend_from_slice(&3u16.to_le_bytes());
    // Tag 0x010F Make (ASCII = 2)
    tiff.extend_from_slice(&0x010Fu16.to_le_bytes());
    tiff.extend_from_slice(&2u16.to_le_bytes());
    tiff.extend_from_slice(&(make_bytes.len() as u32).to_le_bytes());
    tiff.extend_from_slice(&make_off.to_le_bytes());

    // Tag 0x0110 Model (ASCII = 2)
    tiff.extend_from_slice(&0x0110u16.to_le_bytes());
    tiff.extend_from_slice(&2u16.to_le_bytes());
    tiff.extend_from_slice(&(model_bytes.len() as u32).to_le_bytes());
    tiff.extend_from_slice(&model_off.to_le_bytes());

    // Tag 0x8769 ExifIFDPointer (LONG = 4)
    tiff.extend_from_slice(&0x8769u16.to_le_bytes());
    tiff.extend_from_slice(&4u16.to_le_bytes());
    tiff.extend_from_slice(&1u32.to_le_bytes());
    tiff.extend_from_slice(&exif_ifd_off.to_le_bytes());

    // Next IFD = 0
    tiff.extend_from_slice(&0u32.to_le_bytes());

    tiff.extend_from_slice(make_bytes);
    tiff.extend_from_slice(model_bytes);

    // ExifIFD at exif_ifd_off
    tiff.extend_from_slice(&1u16.to_le_bytes());
    tiff.extend_from_slice(&0x9003u16.to_le_bytes());
    tiff.extend_from_slice(&2u16.to_le_bytes());
    tiff.extend_from_slice(&(dt_bytes.len() as u32).to_le_bytes());
    tiff.extend_from_slice(&dt_off.to_le_bytes());
    tiff.extend_from_slice(&0u32.to_le_bytes());
    tiff.extend_from_slice(dt_bytes);

    let mut jpeg = Vec::new();
    jpeg.extend_from_slice(&[0xFF, 0xD8]); // SOI
    jpeg.extend_from_slice(&[0xFF, 0xE1]); // APP1
    let app1_len = (2 + 6 + tiff.len()) as u16;
    jpeg.extend_from_slice(&app1_len.to_be_bytes());
    jpeg.extend_from_slice(b"Exif\0\0");
    jpeg.extend_from_slice(&tiff);
    jpeg.extend_from_slice(&[0xFF, 0xD9]); // EOI

    let parsed = parse_jpeg_exif(&jpeg);
    assert_eq!(parsed.camera.as_deref(), Some("Fujifilm X-T5"));
    assert!(parsed.captured_at_unix_ms.is_some());
}

fn build_tar_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in entries {
        let mut header = [0u8; 512];
        let name_bytes = name.as_bytes();
        header[..name_bytes.len()].copy_from_slice(name_bytes);
        let size_oct = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size_oct.as_bytes());
        header[156] = b'0';
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        let pad = (512 - (data.len() % 512)) % 512;
        out.resize(out.len() + pad, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn build_zip_store_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in entries {
        let nb = name.as_bytes();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(nb);
        out.extend_from_slice(data);
    }
    out
}

#[test]
fn archive_takeout_pdf_scanner_and_redaction_work_in_ram() {
    use image::{ImageFormat, Rgb, RgbImage};
    use meshvault_crypto::{Argon2Params, SecretString, VaultHeader};
    use meshvault_import::{
        import_tar_bytes_in_ram, import_zip_store_bytes_in_ram, redact_image_regions_in_ram,
        wrap_jpeg_as_pdf_in_ram, RedactionRect,
    };
    use meshvault_storage::{VaultCatalog, VaultLayout};
    use std::io::Cursor;

    let tmp = TempDir::new().unwrap();
    let layout = VaultLayout::new(tmp.path());
    let pass = SecretString::from("archive-pass".to_string());
    let (hdr, mvk) =
        VaultHeader::create_with_passphrase(&pass, Argon2Params::fast_test(), 1_700_000_000_000, 0)
            .unwrap();
    layout.write_header_pair(&hdr).unwrap();
    let mut catalog = VaultCatalog::new(hdr.vault_id, 1_700_000_000_000);
    let root = catalog.root_folder_id;

    // 1. In-RAM JPEG generation + redaction + PDF Document Scanner wrapper
    let mut img = RgbImage::from_pixel(32, 32, Rgb([240, 240, 240]));
    let mut jpeg_buf = Vec::new();
    image::DynamicImage::ImageRgb8(img.clone())
        .write_to(&mut Cursor::new(&mut jpeg_buf), ImageFormat::Jpeg)
        .unwrap();

    let redacted = redact_image_regions_in_ram(
        "image/jpeg",
        &jpeg_buf,
        &[RedactionRect {
            x: 4,
            y: 4,
            width: 12,
            height: 12,
        }],
    )
    .expect("redact");
    let decoded_redacted = image::load_from_memory(&redacted).unwrap().to_rgb8();
    assert!(decoded_redacted.get_pixel(8, 8).0[0] < 40);
    // Unused mut suppression not needed when we keep img clean
    let _ = &mut img;

    let pdf_bytes = wrap_jpeg_as_pdf_in_ram(&redacted, 32, 32).expect("pdf");
    assert!(pdf_bytes.starts_with(b"%PDF-1.4"));
    assert!(pdf_bytes.windows(5).any(|w| w == b"%%EOF"));

    // 2. TAR + Google Takeout JSON sidecar import strictly in RAM
    let takeout_json = br#"{"photoTakenTime":{"timestamp":"1712345678"}}"#;
    let tar_bytes = build_tar_archive(&[
        ("Takeout/Vacation/beach.jpg", &jpeg_buf),
        ("Takeout/Vacation/beach.jpg.json", takeout_json),
    ]);
    let tar_report = import_tar_bytes_in_ram(
        &layout,
        &mvk,
        &mut catalog,
        &tar_bytes,
        root,
        1_700_000_001_000,
    )
    .expect("tar import");
    assert_eq!(tar_report.imported_files, 1);
    assert_eq!(tar_report.takeout_timestamps_applied, 1);
    let imported = catalog.search_media("beach");
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].captured_at_unix_ms, Some(1_712_345_678_000));

    // 3. ZIP Store import strictly in RAM
    let zip_bytes = build_zip_store_archive(&[("Scanner/contract.pdf", &pdf_bytes)]);
    let zip_report = import_zip_store_bytes_in_ram(
        &layout,
        &mvk,
        &mut catalog,
        &zip_bytes,
        root,
        1_700_000_002_000,
    )
    .expect("zip import");
    assert_eq!(zip_report.imported_files, 1);
    assert_eq!(catalog.search_media("contract").len(), 1);
}
