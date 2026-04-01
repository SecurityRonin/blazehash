#[cfg(feature = "forensic-image")]
mod ewf_backend;

use anyhow::{bail, Result};
use std::fmt;
use std::path::Path;

/// Supported forensic image formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageFormat {
    Ewf,
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
            _ => bail!("unsupported forensic image format: {}", path.display()),
        }
    }
}

impl fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImageFormat::Ewf => write!(f, "EWF (E01)"),
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
}

impl fmt::Display for ImageVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Image:         {}", self.path)?;
        writeln!(f, "Format:        {}", self.format)?;

        let size = self.media_size;
        if size >= 1024 * 1024 * 1024 {
            writeln!(f, "Media size:    {size} bytes ({:.1} GiB)", size as f64 / (1024.0 * 1024.0 * 1024.0))?;
        } else if size >= 1024 * 1024 {
            writeln!(f, "Media size:    {size} bytes ({:.1} MiB)", size as f64 / (1024.0 * 1024.0))?;
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

/// Verify a forensic disk image, auto-detecting format from the file extension.
pub fn verify_image(path: &Path) -> Result<ImageVerification> {
    let format = ImageFormat::detect(path)?;

    match format {
        #[cfg(feature = "forensic-image")]
        ImageFormat::Ewf => ewf_backend::verify_ewf(path),
        #[cfg(not(feature = "forensic-image"))]
        _ => bail!("forensic image support not compiled (enable 'forensic-image' feature)"),
    }
}
