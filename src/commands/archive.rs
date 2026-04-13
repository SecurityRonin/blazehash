//! Hash file contents inside tar (.tar, .tar.gz, .tgz) and zip archives.
//!
//! Produces a blazehash manifest of all archive members without extracting to disk.

use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

fn detect_format(path: &Path) -> &'static str {
    let s = path.to_str().unwrap_or("");
    if s.ends_with(".tar.gz") || s.ends_with(".tgz") {
        "tar+gzip"
    } else if s.ends_with(".tar") {
        "tar"
    } else if s.ends_with(".zip") {
        "zip"
    } else {
        "unknown"
    }
}

pub fn hash_archive<W: Write>(archive_path: &Path, out: &mut W) -> Result<()> {
    let kind = detect_format(archive_path);
    writeln!(out, "## source: {}", archive_path.display())?;
    writeln!(out, "## format: {kind}")?;
    match kind {
        "zip" => hash_zip(archive_path, out),
        "tar" => hash_tar(archive_path, false, out),
        "tar+gzip" => hash_tar(archive_path, true, out),
        _ => bail!("unsupported archive format: {}", archive_path.display()),
    }
}

#[cfg(feature = "archive")]
fn hash_zip<W: Write>(path: &Path, out: &mut W) -> Result<()> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;
        let hash = blake3::hash(&data).to_hex().to_string();
        writeln!(out, "blake3  {hash}  {name}")?;
    }
    Ok(())
}

#[cfg(not(feature = "archive"))]
fn hash_zip<W: Write>(_path: &Path, _out: &mut W) -> Result<()> {
    anyhow::bail!("zip support requires --features archive")
}

#[cfg(feature = "archive")]
fn hash_tar<W: Write>(path: &Path, gzip: bool, out: &mut W) -> Result<()> {
    let file = std::fs::File::open(path)?;
    if gzip {
        let decoder = flate2::read::GzDecoder::new(file);
        hash_tar_reader(decoder, out)
    } else {
        hash_tar_reader(file, out)
    }
}

#[cfg(not(feature = "archive"))]
fn hash_tar<W: Write>(_path: &Path, _gzip: bool, _out: &mut W) -> Result<()> {
    anyhow::bail!("tar support requires --features archive")
}

#[cfg(feature = "archive")]
fn hash_tar_reader<R: std::io::Read, W: Write>(reader: R, out: &mut W) -> Result<()> {
    use std::io::Read;
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();
        if entry.header().entry_type().is_file() {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            let hash = blake3::hash(&data).to_hex().to_string();
            writeln!(out, "blake3  {hash}  {path}")?;
        }
    }
    Ok(())
}
