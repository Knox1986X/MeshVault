use std::io::Write;

use crate::error::ImportError;

/// Wraps a scanned document JPEG in a single-page PDF 1.4 container purely in RAM.
/// Used by the Document Scanner mode before streaming directly into `.mvb`.
pub fn wrap_jpeg_as_pdf_in_ram(
    jpeg_bytes: &[u8],
    width_px: u32,
    height_px: u32,
) -> Result<Vec<u8>, ImportError> {
    if !jpeg_bytes.starts_with(&[0xFF, 0xD8]) || width_px == 0 || height_px == 0 {
        return Err(ImportError::InvalidImage(
            "expected valid non-empty JPEG for PDF scanner wrapper".to_string(),
        ));
    }

    let w_pt = width_px.max(1);
    let h_pt = height_px.max(1);
    let content_stream = format!("q\n{w_pt} 0 0 {h_pt} 0 0 cm\n/Im0 Do\nQ\n");

    let mut pdf = Vec::with_capacity(jpeg_bytes.len() + 1024);
    pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets = [0usize; 6];

    offsets[1] = pdf.len();
    writeln!(pdf, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj")
        .map_err(|e| ImportError::InvalidImage(e.to_string()))?;

    offsets[2] = pdf.len();
    writeln!(
        pdf,
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj"
    )
    .map_err(|e| ImportError::InvalidImage(e.to_string()))?;

    offsets[3] = pdf.len();
    writeln!(
        pdf,
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w_pt} {h_pt}] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>\nendobj"
    )
    .map_err(|e| ImportError::InvalidImage(e.to_string()))?;

    offsets[4] = pdf.len();
    writeln!(
        pdf,
        "4 0 obj\n<< /Type /XObject /Subtype /Image /Width {width_px} /Height {height_px} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {} >>\nstream",
        jpeg_bytes.len()
    )
    .map_err(|e| ImportError::InvalidImage(e.to_string()))?;
    pdf.extend_from_slice(jpeg_bytes);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");

    offsets[5] = pdf.len();
    writeln!(
        pdf,
        "5 0 obj\n<< /Length {} >>\nstream\n{content_stream}endstream\nendobj",
        content_stream.len()
    )
    .map_err(|e| ImportError::InvalidImage(e.to_string()))?;

    let xref_offset = pdf.len();
    writeln!(pdf, "xref\n0 6\n0000000000 65535 f ")
        .map_err(|e| ImportError::InvalidImage(e.to_string()))?;
    for off in &offsets[1..=5] {
        writeln!(pdf, "{off:010} 00000 n ")
            .map_err(|e| ImportError::InvalidImage(e.to_string()))?;
    }
    writeln!(
        pdf,
        "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF"
    )
    .map_err(|e| ImportError::InvalidImage(e.to_string()))?;

    Ok(pdf)
}
