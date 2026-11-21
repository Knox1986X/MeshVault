use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use meshvault_storage::MediaKind;
use serde::{Deserialize, Serialize};

use crate::error::ImportError;
use crate::exif::classify_by_extension;

/// Options controlling recursive directory scanning.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_depth: usize,
    pub follow_symlinks: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_depth: 64,
            follow_symlinks: false,
        }
    }
}

/// Single discovered source file ready for preview and encrypted import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedItem {
    pub relative_folder_segments: Vec<String>,
    pub file_name: String,
    pub source_path: PathBuf,
    pub size_bytes: u64,
    pub kind: MediaKind,
}

/// Folder branch summary shown on the pre-import preview screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedFolderSummary {
    pub relative_path: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub selected: bool,
}

/// Counts of discovered files grouped by MediaKind.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KindCounts {
    pub photos: usize,
    pub videos: usize,
    pub raw_photos: usize,
    pub documents: usize,
    pub animations: usize,
    pub audio_notes: usize,
    pub markdown_notes: usize,
}

/// Complete preview model computed before any bytes are encrypted into the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportTreePreview {
    pub root_folder_name: String,
    pub folders: Vec<ScannedFolderSummary>,
    pub items: Vec<ScannedItem>,
    pub total_bytes: u64,
    pub counts: KindCounts,
}

/// Recursively scans `root_dir` with symlink-loop protection and depth bounds.
pub fn scan_directory_tree(
    root_dir: &Path,
    options: &ScanOptions,
) -> Result<ImportTreePreview, ImportError> {
    if !root_dir.is_dir() {
        return Err(ImportError::NotADirectory(
            root_dir.to_string_lossy().to_string(),
        ));
    }

    let root_folder_name = root_dir
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("ImportedFolder")
        .to_string();

    let mut visited_dirs = BTreeSet::new();
    if let Ok(canon) = fs::canonicalize(root_dir) {
        visited_dirs.insert(canon);
    }

    let mut items = Vec::new();
    let mut folder_stats: std::collections::BTreeMap<String, (usize, u64)> =
        std::collections::BTreeMap::new();
    let mut counts = KindCounts::default();
    let mut total_bytes = 0u64;

    let initial_segments = vec![root_folder_name.clone()];
    scan_recursive(
        root_dir,
        &initial_segments,
        0,
        options,
        &mut visited_dirs,
        &mut items,
        &mut folder_stats,
        &mut counts,
        &mut total_bytes,
    )?;

    let folders = folder_stats
        .into_iter()
        .map(|(relative_path, (file_count, bytes))| ScannedFolderSummary {
            relative_path,
            file_count,
            total_bytes: bytes,
            selected: true,
        })
        .collect();

    Ok(ImportTreePreview {
        root_folder_name,
        folders,
        items,
        total_bytes,
        counts,
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_recursive(
    current_dir: &Path,
    segments: &[String],
    depth: usize,
    options: &ScanOptions,
    visited_dirs: &mut BTreeSet<PathBuf>,
    items: &mut Vec<ScannedItem>,
    folder_stats: &mut std::collections::BTreeMap<String, (usize, u64)>,
    counts: &mut KindCounts,
    total_bytes: &mut u64,
) -> Result<(), ImportError> {
    if depth > options.max_depth {
        return Err(ImportError::MaxDepthExceeded(
            current_dir.to_string_lossy().to_string(),
        ));
    }

    let rel_key = segments.join("/");
    folder_stats.entry(rel_key.clone()).or_insert((0, 0));

    let mut entries: Vec<_> = fs::read_dir(current_dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        let file_type = meta.file_type();

        if file_type.is_symlink() {
            if !options.follow_symlinks {
                continue;
            }
            let Ok(target_meta) = fs::metadata(&path) else {
                continue;
            };
            if target_meta.is_dir() {
                let Ok(canon) = fs::canonicalize(&path) else {
                    continue;
                };
                if !visited_dirs.insert(canon) {
                    // Prevent symlink directory cycles.
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                let mut next_segments = segments.to_vec();
                next_segments.push(name);
                scan_recursive(
                    &path,
                    &next_segments,
                    depth + 1,
                    options,
                    visited_dirs,
                    items,
                    folder_stats,
                    counts,
                    total_bytes,
                )?;
            } else if target_meta.is_file() {
                record_file(
                    &path,
                    segments,
                    target_meta.len(),
                    &rel_key,
                    items,
                    folder_stats,
                    counts,
                    total_bytes,
                );
            }
            continue;
        }

        if file_type.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            let mut next_segments = segments.to_vec();
            next_segments.push(name);
            scan_recursive(
                &path,
                &next_segments,
                depth + 1,
                options,
                visited_dirs,
                items,
                folder_stats,
                counts,
                total_bytes,
            )?;
        } else if file_type.is_file() {
            record_file(
                &path,
                segments,
                meta.len(),
                &rel_key,
                items,
                folder_stats,
                counts,
                total_bytes,
            );
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_file(
    path: &Path,
    segments: &[String],
    size_bytes: u64,
    rel_key: &str,
    items: &mut Vec<ScannedItem>,
    folder_stats: &mut std::collections::BTreeMap<String, (usize, u64)>,
    counts: &mut KindCounts,
    total_bytes: &mut u64,
) {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unnamed")
        .to_string();
    let (kind, _) = classify_by_extension(path);

    match kind {
        MediaKind::Photo => counts.photos += 1,
        MediaKind::Video => counts.videos += 1,
        MediaKind::RawPhoto => counts.raw_photos += 1,
        MediaKind::DocumentPdf => counts.documents += 1,
        MediaKind::Animation => counts.animations += 1,
        MediaKind::AudioNote => counts.audio_notes += 1,
        MediaKind::MarkdownNote => counts.markdown_notes += 1,
    }

    *total_bytes = total_bytes.saturating_add(size_bytes);
    let stat = folder_stats.entry(rel_key.to_string()).or_insert((0, 0));
    stat.0 += 1;
    stat.1 = stat.1.saturating_add(size_bytes);

    items.push(ScannedItem {
        relative_folder_segments: segments.to_vec(),
        file_name,
        source_path: path.to_path_buf(),
        size_bytes,
        kind,
    });
}
