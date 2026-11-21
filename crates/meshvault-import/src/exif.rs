use std::io::Cursor;
use std::path::Path;

use image::{imageops::FilterType, GenericImageView, ImageFormat};
use meshvault_storage::MediaKind;
use zeroize::Zeroizing;

/// Extracted metadata and in-memory thumbnails for an imported media file.
#[derive(Debug, Clone)]
pub struct ExtractedMediaMeta {
    pub kind: MediaKind,
    pub mime_type: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub exif_camera: Option<String>,
    pub captured_at_unix_ms: Option<u64>,
    pub phash: Option<u64>,
    pub micro_thumb: Option<Vec<u8>>,
    pub pack_thumb: Option<Vec<u8>>,
}

/// Classifies a file by extension into MediaKind and canonical MIME type.
pub fn classify_by_extension(path: &Path) -> (MediaKind, &'static str) {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "jpg" | "jpeg" => (MediaKind::Photo, "image/jpeg"),
        "png" => (MediaKind::Photo, "image/png"),
        "webp" => (MediaKind::Photo, "image/webp"),
        "avif" => (MediaKind::Photo, "image/avif"),
        "heic" | "heif" => (MediaKind::Photo, "image/heic"),
        "jxl" => (MediaKind::Photo, "image/jxl"),
        "gif" => (MediaKind::Animation, "image/gif"),
        "dng" => (MediaKind::RawPhoto, "image/x-adobe-dng"),
        "cr2" | "cr3" => (MediaKind::RawPhoto, "image/x-canon-raw"),
        "nef" => (MediaKind::RawPhoto, "image/x-nikon-nef"),
        "arw" => (MediaKind::RawPhoto, "image/x-sony-arw"),
        "mp4" => (MediaKind::Video, "video/mp4"),
        "mkv" => (MediaKind::Video, "video/x-matroska"),
        "mov" => (MediaKind::Video, "video/quicktime"),
        "webm" => (MediaKind::Video, "video/webm"),
        "pdf" => (MediaKind::DocumentPdf, "application/pdf"),
        "m4a" => (MediaKind::AudioNote, "audio/mp4"),
        "ogg" | "opus" => (MediaKind::AudioNote, "audio/ogg"),
        "wav" => (MediaKind::AudioNote, "audio/wav"),
        "mp3" => (MediaKind::AudioNote, "audio/mpeg"),
        "md" => (MediaKind::MarkdownNote, "text/markdown"),
        _ => (MediaKind::Photo, "application/octet-stream"),
    }
}

/// Extracts EXIF metadata, image dimensions, 64-bit perceptual dHash, and RAM-only thumbnails.
pub fn extract_metadata_and_thumbnails(
    path: &Path,
    bytes: &[u8],
    generate_thumbnails: bool,
) -> ExtractedMediaMeta {
    let (kind, mime) = classify_by_extension(path);
    let mut meta = ExtractedMediaMeta {
        kind,
        mime_type: mime.to_string(),
        width: None,
        height: None,
        exif_camera: None,
        captured_at_unix_ms: None,
        phash: None,
        micro_thumb: None,
        pack_thumb: None,
    };

    if kind == MediaKind::Photo && mime == "image/jpeg" {
        let exif = parse_jpeg_exif(bytes);
        meta.exif_camera = exif.camera;
        meta.captured_at_unix_ms = exif.captured_at_unix_ms;
    }

    if matches!(kind, MediaKind::Photo | MediaKind::Animation) {
        if let Ok(img) = image::load_from_memory(bytes) {
            let (w, h) = img.dimensions();
            meta.width = Some(w);
            meta.height = Some(h);
            meta.phash = Some(compute_dhash_64(&img));

            if generate_thumbnails {
                let micro = img.thumbnail(32, 32);
                let mut micro_buf = Zeroizing::new(Vec::new());
                if micro
                    .write_to(&mut Cursor::new(&mut *micro_buf), ImageFormat::Jpeg)
                    .is_ok()
                {
                    meta.micro_thumb = Some(micro_buf.to_vec());
                }

                let tile = img.thumbnail(256, 256);
                let mut tile_buf = Zeroizing::new(Vec::new());
                if tile
                    .write_to(&mut Cursor::new(&mut *tile_buf), ImageFormat::Jpeg)
                    .is_ok()
                {
                    meta.pack_thumb = Some(tile_buf.to_vec());
                }
            }
        }
    }

    meta
}

/// Computes a 64-bit difference hash (dHash) in RAM for visual duplicate detection.
pub fn compute_dhash_64(img: &image::DynamicImage) -> u64 {
    let small = img.resize_exact(9, 8, FilterType::Triangle).to_luma8();
    let mut hash: u64 = 0;
    let mut bit: u32 = 0;
    for y in 0..8u32 {
        for x in 0..8u32 {
            let left = small.get_pixel(x, y)[0];
            let right = small.get_pixel(x + 1, y)[0];
            if left > right {
                hash |= 1u64 << bit;
            }
            bit += 1;
        }
    }
    hash
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedExif {
    pub camera: Option<String>,
    pub captured_at_unix_ms: Option<u64>,
}

/// Pure-Rust JPEG APP1 EXIF parser extracting camera Make/Model and DateTimeOriginal.
pub fn parse_jpeg_exif(data: &[u8]) -> ParsedExif {
    let mut out = ParsedExif::default();
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return out;
    }

    let mut pos = 2usize;
    while pos + 4 <= data.len() {
        if data[pos] != 0xFF {
            break;
        }
        let marker = data[pos + 1];
        if marker == 0xDA || marker == 0xD9 {
            break;
        }
        if marker == 0x00 || (0xD0..=0xD7).contains(&marker) {
            pos += 2;
            continue;
        }
        let seg_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if seg_len < 2 || pos + 2 + seg_len > data.len() {
            break;
        }
        if marker == 0xE1 && seg_len >= 8 && &data[pos + 4..pos + 10] == b"Exif\0\0" {
            let tiff = &data[pos + 10..pos + 2 + seg_len];
            parse_tiff_ifd(tiff, &mut out);
            break;
        }
        pos += 2 + seg_len;
    }

    out
}

fn parse_tiff_ifd(tiff: &[u8], out: &mut ParsedExif) {
    if tiff.len() < 8 {
        return;
    }
    let big_endian = match &tiff[0..2] {
        b"MM" => true,
        b"II" => false,
        _ => return,
    };
    if read_u16(tiff, 2, big_endian) != Some(42) {
        return;
    }
    let Some(ifd0_offset) = read_u32(tiff, 4, big_endian) else {
        return;
    };

    let mut make: Option<String> = None;
    let mut model: Option<String> = None;
    let mut exif_ifd_offset: Option<u32> = None;
    let mut fallback_datetime: Option<u64> = None;

    scan_ifd(
        tiff,
        ifd0_offset as usize,
        big_endian,
        |tag, val| match tag {
            0x010F => make = read_ascii_tag(tiff, val),
            0x0110 => model = read_ascii_tag(tiff, val),
            0x0132 => {
                if let Some(s) = read_ascii_tag(tiff, val) {
                    fallback_datetime = parse_exif_datetime_unix_ms(&s);
                }
            }
            0x8769 => exif_ifd_offset = val.as_u32(big_endian),
            _ => {}
        },
    );

    if let Some(offset) = exif_ifd_offset {
        scan_ifd(tiff, offset as usize, big_endian, |tag, val| {
            if tag == 0x9003 {
                if let Some(s) = read_ascii_tag(tiff, val) {
                    out.captured_at_unix_ms = parse_exif_datetime_unix_ms(&s);
                }
            }
        });
    }

    if out.captured_at_unix_ms.is_none() {
        out.captured_at_unix_ms = fallback_datetime;
    }

    out.camera = match (make, model) {
        (Some(mk), Some(md)) => {
            if md
                .to_ascii_lowercase()
                .starts_with(&mk.to_ascii_lowercase())
            {
                Some(md)
            } else {
                Some(format!("{mk} {md}"))
            }
        }
        (None, Some(md)) => Some(md),
        (Some(mk), None) => Some(mk),
        (None, None) => None,
    };
}

struct IfdValue<'a> {
    field_type: u16,
    count: u32,
    raw_value_bytes: &'a [u8],
}

impl<'a> IfdValue<'a> {
    fn as_u32(&self, big_endian: bool) -> Option<u32> {
        if self.field_type == 4 && self.count >= 1 {
            read_u32(self.raw_value_bytes, 0, big_endian)
        } else {
            None
        }
    }
}

fn scan_ifd<F>(tiff: &[u8], offset: usize, big_endian: bool, mut visitor: F)
where
    F: FnMut(u16, IfdValue<'_>),
{
    let Some(count) = read_u16(tiff, offset, big_endian) else {
        return;
    };
    let entries_start = offset + 2;
    for i in 0..usize::from(count) {
        let entry_off = entries_start + i * 12;
        if entry_off + 12 > tiff.len() {
            break;
        }
        let Some(tag) = read_u16(tiff, entry_off, big_endian) else {
            break;
        };
        let Some(field_type) = read_u16(tiff, entry_off + 2, big_endian) else {
            break;
        };
        let Some(val_count) = read_u32(tiff, entry_off + 4, big_endian) else {
            break;
        };
        let raw_value_bytes = &tiff[entry_off + 8..entry_off + 12];
        visitor(
            tag,
            IfdValue {
                field_type,
                count: val_count,
                raw_value_bytes,
            },
        );
    }
}

fn read_ascii_tag(tiff: &[u8], val: IfdValue<'_>) -> Option<String> {
    if val.field_type != 2 || val.count == 0 {
        return None;
    }
    let len = val.count as usize;
    let slice = if len <= 4 {
        &val.raw_value_bytes[..len]
    } else {
        let big_endian = &tiff[0..2] == b"MM";
        let off = read_u32(val.raw_value_bytes, 0, big_endian)? as usize;
        if off.checked_add(len)? > tiff.len() {
            return None;
        }
        &tiff[off..off + len]
    };
    let trimmed = slice.split(|b| *b == 0).next()?;
    let s = std::str::from_utf8(trimmed).ok()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn read_u16(buf: &[u8], off: usize, big_endian: bool) -> Option<u16> {
    let b = buf.get(off..off + 2)?;
    Some(if big_endian {
        u16::from_be_bytes([b[0], b[1]])
    } else {
        u16::from_le_bytes([b[0], b[1]])
    })
}

fn read_u32(buf: &[u8], off: usize, big_endian: bool) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(if big_endian {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    })
}

/// Parses EXIF timestamp `YYYY:MM:DD HH:MM:SS` into UTC Unix milliseconds.
pub fn parse_exif_datetime_unix_ms(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split(" ").collect();
    if parts.len() != 2 {
        return None;
    }
    let d: Vec<i64> = parts[0].split(":").filter_map(|p| p.parse().ok()).collect();
    let t: Vec<i64> = parts[1].split(":").filter_map(|p| p.parse().ok()).collect();
    if d.len() != 3 || t.len() != 3 {
        return None;
    }
    let (year, month, day) = (d[0], d[1], d[2]);
    let (hour, min, sec) = (t[0], t[1], t[2]);
    if !(1970..=2100).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3_600 + min * 60 + sec;
    u64::try_from(secs).ok().map(|v| v * 1000)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
