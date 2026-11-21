use std::collections::BTreeMap;

use meshvault_crypto::MasterVaultKey;
use meshvault_storage::VaultCatalog;
use meshvault_storage::VaultLayout;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ImportError;
use crate::{DedupPolicy, ImportPipeline};

#[derive(Debug, Deserialize)]
struct TakeoutTime {
    timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TakeoutSidecar {
    photo_taken_time: Option<TakeoutTime>,
}

/// Summary of an in-RAM archive import (TAR / uncompressed ZIP / Google Takeout JSON).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveImportReport {
    pub imported_files: usize,
    pub takeout_timestamps_applied: usize,
}

/// Imports a POSIX TAR archive directly from RAM without extracting any plaintext files to disk.
/// Supports Google Takeout `.json` sidecars (`photoTakenTime.timestamp`).
pub fn import_tar_bytes_in_ram(
    layout: &VaultLayout,
    mvk: &MasterVaultKey,
    catalog: &mut VaultCatalog,
    tar_bytes: &[u8],
    target_parent_id: Uuid,
    now_unix_ms: u64,
) -> Result<ArchiveImportReport, ImportError> {
    let entries = parse_tar_entries(tar_bytes);
    import_archive_entries_in_ram(layout, mvk, catalog, entries, target_parent_id, now_unix_ms)
}

/// Imports a ZIP (Store / method 0) archive directly from RAM without extracting to disk.
pub fn import_zip_store_bytes_in_ram(
    layout: &VaultLayout,
    mvk: &MasterVaultKey,
    catalog: &mut VaultCatalog,
    zip_bytes: &[u8],
    target_parent_id: Uuid,
    now_unix_ms: u64,
) -> Result<ArchiveImportReport, ImportError> {
    let entries = parse_zip_store_entries(zip_bytes);
    import_archive_entries_in_ram(layout, mvk, catalog, entries, target_parent_id, now_unix_ms)
}

fn import_archive_entries_in_ram<'a>(
    layout: &VaultLayout,
    mvk: &MasterVaultKey,
    catalog: &mut VaultCatalog,
    entries: Vec<(String, &'a [u8])>,
    target_parent_id: Uuid,
    now_unix_ms: u64,
) -> Result<ArchiveImportReport, ImportError> {
    let mut takeout_times: BTreeMap<String, u64> = BTreeMap::new();
    let mut media_files: Vec<(String, &'a [u8])> = Vec::new();

    for (raw_path, data) in entries {
        let norm = raw_path.trim_start_matches("./").trim_start_matches('/');
        if norm.is_empty() || norm.contains("..") {
            continue;
        }
        if norm.to_ascii_lowercase().ends_with(".json") {
            if let Ok(sidecar) = serde_json::from_slice::<TakeoutSidecar>(data) {
                if let Some(ts_str) = sidecar.photo_taken_time.and_then(|t| t.timestamp) {
                    if let Ok(secs) = ts_str.parse::<u64>() {
                        let base_key = norm.strip_suffix(".json").unwrap_or(norm).to_string();
                        takeout_times.insert(base_key, secs.saturating_mul(1000));
                    }
                }
            }
            continue;
        }
        media_files.push((norm.to_string(), data));
    }

    let mut imported_files = 0usize;
    let mut takeout_timestamps_applied = 0usize;

    for (norm_path, bytes) in media_files {
        if bytes.is_empty() {
            continue;
        }
        let mut parts: Vec<String> = norm_path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        let Some(file_name) = parts.pop() else {
            continue;
        };
        let captured_override = takeout_times.get(&norm_path).copied();
        if captured_override.is_some() {
            takeout_timestamps_applied += 1;
        }
        let res = ImportPipeline::import_bytes_item(
            layout,
            mvk,
            catalog,
            target_parent_id,
            &parts,
            &file_name,
            bytes,
            DedupPolicy::SkipDuplicate,
            captured_override,
            now_unix_ms,
        )?;
        if !res.deduplicated_skip {
            imported_files += 1;
        }
    }

    Ok(ArchiveImportReport {
        imported_files,
        takeout_timestamps_applied,
    })
}

fn parse_tar_entries(data: &[u8]) -> Vec<(String, &[u8])> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 512 <= data.len() {
        let header = &data[offset..offset + 512];
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let name_end = header[0..100].iter().position(|&b| b == 0).unwrap_or(100);
        let name = String::from_utf8_lossy(&header[..name_end]).to_string();
        let size_str = String::from_utf8_lossy(&header[124..136]);
        let size = usize::from_str_radix(size_str.trim_matches(['\0', ' ']), 8).unwrap_or(0);
        let typeflag = header[156];
        offset += 512;

        let padded = size.div_ceil(512) * 512;
        if offset + size > data.len() {
            break;
        }
        if typeflag == b'0' || typeflag == 0 {
            out.push((name, &data[offset..offset + size]));
        }
        offset = offset.saturating_add(padded);
    }
    out
}

fn parse_zip_store_entries(data: &[u8]) -> Vec<(String, &[u8])> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 30 <= data.len() {
        if &data[pos..pos + 4] != b"PK\x03\x04" {
            break;
        }
        let method = u16::from_le_bytes([data[pos + 8], data[pos + 9]]);
        let comp_size = u32::from_le_bytes([
            data[pos + 18],
            data[pos + 19],
            data[pos + 20],
            data[pos + 21],
        ]) as usize;
        let name_len = u16::from_le_bytes([data[pos + 26], data[pos + 27]]) as usize;
        let extra_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;
        let name_start = pos + 30;
        let data_start = name_start + name_len + extra_len;
        if data_start + comp_size > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[name_start..name_start + name_len]).to_string();
        if method == 0 && !name.ends_with('/') {
            out.push((name, &data[data_start..data_start + comp_size]));
        }
        pos = data_start + comp_size;
    }
    out
}
