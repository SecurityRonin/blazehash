#[cfg(feature = "forensic-image")]
mod ewf_backend;

use anyhow::{bail, Result};
use std::fmt;
use std::path::Path;

/// Supported forensic image formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageFormat {
    Ewf,
    /// Raw/DD images (.dd, .raw, .img, .bin) verified via sidecar hash files.
    RawDd,
}

impl ImageFormat {
    /// Detect format from file extension and magic bytes.
    pub fn detect(path: &Path) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        match ext.as_str() {
            "e01" | "ex01" | "l01" | "lx01" => Ok(ImageFormat::Ewf),
            "dd" | "raw" | "img" | "bin" => Ok(ImageFormat::RawDd),
            _ => {
                // Unknown extension — check if a sidecar exists before failing.
                if has_sidecar(path) {
                    Ok(ImageFormat::RawDd)
                } else {
                    bail!("unsupported forensic image format: {}", path.display())
                }
            }
        }
    }
}

impl fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImageFormat::Ewf => write!(f, "EWF (E01)"),
            ImageFormat::RawDd => write!(f, "Raw/DD"),
        }
    }
}

/// Metadata extracted from the forensic image.
#[derive(Debug, Clone)]
pub struct ImageMetadata {
    pub case_number: Option<String>,
    pub examiner: Option<String>,
    pub description: Option<String>,
    pub acquiry_software: Option<String>,
}

/// Result of verifying a forensic disk image.
#[derive(Debug, Clone)]
pub struct ImageVerification {
    pub format: ImageFormat,
    pub path: String,
    pub media_size: u64,
    pub stored_md5: Option<String>,
    pub stored_sha1: Option<String>,
    pub computed_md5: Option<String>,
    pub computed_sha1: Option<String>,
    pub md5_match: Option<bool>,
    pub sha1_match: Option<bool>,
    pub metadata: Option<ImageMetadata>,
    /// Non-empty only for RawDd images verified via sidecars.
    pub sidecar_results: Vec<SidecarResult>,
}

impl fmt::Display for ImageVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Image:         {}", self.path)?;
        writeln!(f, "Format:        {}", self.format)?;

        let size = self.media_size;
        if size >= 1024 * 1024 * 1024 {
            writeln!(
                f,
                "Media size:    {size} bytes ({:.1} GiB)",
                size as f64 / (1024.0 * 1024.0 * 1024.0)
            )?;
        } else if size >= 1024 * 1024 {
            writeln!(
                f,
                "Media size:    {size} bytes ({:.1} MiB)",
                size as f64 / (1024.0 * 1024.0)
            )?;
        } else {
            writeln!(f, "Media size:    {size} bytes")?;
        }

        if let Some(ref md5) = self.stored_md5 {
            writeln!(f, "Stored MD5:    {md5}")?;
        }
        if let Some(ref sha1) = self.stored_sha1 {
            writeln!(f, "Stored SHA1:   {sha1}")?;
        }
        if let Some(ref md5) = self.computed_md5 {
            writeln!(f, "Computed MD5:  {md5}")?;
        }
        if let Some(ref sha1) = self.computed_sha1 {
            writeln!(f, "Computed SHA1: {sha1}")?;
        }

        match self.md5_match {
            Some(true) => writeln!(f, "MD5 match:     PASS")?,
            Some(false) => writeln!(f, "MD5 match:     FAIL")?,
            None => writeln!(f, "MD5 match:     n/a (no stored hash)")?,
        }
        match self.sha1_match {
            Some(true) => writeln!(f, "SHA1 match:    PASS")?,
            Some(false) => writeln!(f, "SHA1 match:    FAIL")?,
            None => {}
        }

        if let Some(ref meta) = self.metadata {
            if let Some(ref v) = meta.case_number {
                writeln!(f, "Case:          {v}")?;
            }
            if let Some(ref v) = meta.examiner {
                writeln!(f, "Examiner:      {v}")?;
            }
            if let Some(ref v) = meta.description {
                writeln!(f, "Description:   {v}")?;
            }
            if let Some(ref v) = meta.acquiry_software {
                writeln!(f, "Software:      {v}")?;
            }
        }

        Ok(())
    }
}

/// The sidecar extensions checked for raw/DD images (in priority order).
const SIDECAR_EXTS: &[(&str, crate::algorithm::Algorithm)] = &[
    ("sha256", crate::algorithm::Algorithm::Sha256),
    ("sha512", crate::algorithm::Algorithm::Sha512),
    ("sha1", crate::algorithm::Algorithm::Sha1),
    ("md5", crate::algorithm::Algorithm::Md5),
    ("blake3", crate::algorithm::Algorithm::Blake3),
];

/// Returns true if at least one sidecar hash file exists beside `path`.
pub fn has_sidecar(path: &Path) -> bool {
    SIDECAR_EXTS.iter().any(|(ext, _)| {
        let sidecar = format!("{}.{}", path.display(), ext);
        std::path::Path::new(&sidecar).exists()
    })
}

/// Verify a raw/DD image against all present sidecar hash files.
///
/// NOTE: Reads the entire image into memory because `hash_bytes` takes `&[u8]`.
/// For very large images a streaming approach would be preferable, but this
/// matches the current public API surface.
pub fn verify_raw_dd(path: &Path) -> Result<Vec<SidecarResult>> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("cannot read image {}: {e}", path.display()))?;

    let mut results = Vec::new();

    for (ext, algo) in SIDECAR_EXTS {
        let sidecar_path = format!("{}.{}", path.display(), ext);
        let sidecar = std::path::Path::new(&sidecar_path);
        if !sidecar.exists() {
            continue;
        }

        let expected_raw = std::fs::read_to_string(sidecar)
            .map_err(|e| anyhow::anyhow!("cannot read sidecar {sidecar_path}: {e}"))?;
        let expected = expected_raw.trim().to_ascii_lowercase();
        let computed = crate::algorithm::hash_bytes(*algo, &data);

        results.push(SidecarResult {
            algo: algo.to_string(),
            expected,
            computed,
        });
    }

    if results.is_empty() {
        bail!("no sidecar hash files found for {}", path.display());
    }

    Ok(results)
}

/// One sidecar verification result.
#[derive(Debug, Clone)]
pub struct SidecarResult {
    pub algo: String,
    pub expected: String,
    pub computed: String,
}

impl SidecarResult {
    pub fn is_match(&self) -> bool {
        self.expected == self.computed
    }
}

/// Verify a forensic disk image, auto-detecting format from the file extension.
pub fn verify_image(path: &Path) -> Result<ImageVerification> {
    let format = ImageFormat::detect(path)?;

    match format {
        ImageFormat::RawDd => {
            // Delegate to the sidecar verifier; build a minimal ImageVerification
            // so callers get a consistent return type.
            let size = std::fs::metadata(path)
                .map(|m| m.len())
                .unwrap_or(0);
            let sidecars = verify_raw_dd(path)?;

            // Populate the legacy fields from the first MD5/SHA1 sidecar if present.
            let stored_md5 = sidecars
                .iter()
                .find(|r| r.algo == "md5")
                .map(|r| r.expected.clone());
            let stored_sha1 = sidecars
                .iter()
                .find(|r| r.algo == "sha1")
                .map(|r| r.expected.clone());
            let computed_md5 = sidecars
                .iter()
                .find(|r| r.algo == "md5")
                .map(|r| r.computed.clone());
            let computed_sha1 = sidecars
                .iter()
                .find(|r| r.algo == "sha1")
                .map(|r| r.computed.clone());
            let md5_match = sidecars
                .iter()
                .find(|r| r.algo == "md5")
                .map(|r| r.is_match());
            let sha1_match = sidecars
                .iter()
                .find(|r| r.algo == "sha1")
                .map(|r| r.is_match());

            Ok(ImageVerification {
                format: ImageFormat::RawDd,
                path: path.display().to_string(),
                media_size: size,
                stored_md5,
                stored_sha1,
                computed_md5,
                computed_sha1,
                md5_match,
                sha1_match,
                metadata: None,
                // Store all sidecar results for the command layer to render.
                sidecar_results: sidecars,
            })
        }
        #[cfg(feature = "forensic-image")]
        ImageFormat::Ewf => ewf_backend::verify_ewf(path),
        #[cfg(not(feature = "forensic-image"))]
        _ => bail!("forensic image support not compiled (enable 'forensic-image' feature)"),
    }
}
