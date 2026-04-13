//! Sector-level raw device hashing.
//!
//! Reads a raw block device (or any file) in fixed-size sector chunks,
//! streaming all data through the selected hash algorithms. Produces
//! one `FileHashResult` for the entire device.

use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

/// Default forensic sector size (512 bytes).
pub const DEFAULT_SECTOR_SIZE: usize = 512;

/// Read buffer size: 1 MiB.
const READ_BUF_SIZE: usize = 1024 * 1024;

/// Detect if the path is likely a raw device.
pub fn is_device_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/dev/") || s.starts_with("\\\\.\\")
}

/// Try to auto-detect the physical sector size for a device.
/// Falls back to `DEFAULT_SECTOR_SIZE` if detection fails.
#[cfg(target_os = "linux")]
pub fn detect_sector_size(path: &Path) -> usize {
    use std::os::unix::io::AsRawFd;
    const BLKSSZGET: libc::c_ulong = 0x1268;
    if let Ok(file) = std::fs::File::open(path) {
        let mut sector_size: libc::c_int = 0;
        let ret = unsafe { libc::ioctl(file.as_raw_fd(), BLKSSZGET, &mut sector_size as *mut _) };
        if ret == 0 && sector_size > 0 {
            return sector_size as usize;
        }
    }
    DEFAULT_SECTOR_SIZE
}

#[cfg(target_os = "macos")]
pub fn detect_sector_size(path: &Path) -> usize {
    use std::os::unix::io::AsRawFd;
    const DKIOCGETBLOCKSIZE: libc::c_ulong = 0x40046418;
    if let Ok(file) = std::fs::File::open(path) {
        let mut block_size: u32 = 0;
        let ret = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                DKIOCGETBLOCKSIZE,
                &mut block_size as *mut _,
            )
        };
        if ret == 0 && block_size > 0 {
            return block_size as usize;
        }
    }
    DEFAULT_SECTOR_SIZE
}

#[cfg(target_os = "windows")]
pub fn detect_sector_size(_path: &Path) -> usize {
    DEFAULT_SECTOR_SIZE
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn detect_sector_size(_path: &Path) -> usize {
    DEFAULT_SECTOR_SIZE
}

/// Hash a raw device or file by reading it sequentially in sector-aligned chunks.
pub fn hash_device(
    path: &Path,
    algorithms: &[Algorithm],
    sector_size: usize,
) -> Result<FileHashResult> {
    let sector_size = if sector_size == 0 {
        DEFAULT_SECTOR_SIZE
    } else {
        sector_size
    };

    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open device/file {}", path.display()))?;

    // Align read buffer to sector boundary
    let buf_size = ((READ_BUF_SIZE / sector_size) * sector_size).max(sector_size);
    let mut buf = vec![0u8; buf_size];

    // Only support crypto (streaming) algorithms; reject fuzzy/full-read ones
    for a in algorithms {
        if a.is_fuzzy() || a.needs_full_read() {
            anyhow::bail!(
                "algorithm {a} is not supported for device hashing (requires full file in memory)"
            );
        }
    }

    use digest::Digest as _;

    enum DynH {
        Blake3(Box<blake3::Hasher>),
        Sha256(Box<sha2::Sha256>),
        Sha512(Box<sha2::Sha512>),
        Sha3_256(Box<sha3::Sha3_256>),
        Sha1(Box<sha1::Sha1>),
        Md5(Box<md5::Md5>),
        Tiger(Box<tiger::Tiger>),
        Whirlpool(Box<whirlpool::Whirlpool>),
    }

    impl DynH {
        fn update(&mut self, data: &[u8]) {
            match self {
                DynH::Blake3(h) => {
                    h.update(data);
                }
                DynH::Sha256(h) => {
                    h.update(data);
                }
                DynH::Sha512(h) => {
                    h.update(data);
                }
                DynH::Sha3_256(h) => {
                    h.update(data);
                }
                DynH::Sha1(h) => {
                    h.update(data);
                }
                DynH::Md5(h) => {
                    h.update(data);
                }
                DynH::Tiger(h) => {
                    h.update(data);
                }
                DynH::Whirlpool(h) => {
                    h.update(data);
                }
            }
        }
        fn finalize_hex(self) -> String {
            match self {
                DynH::Blake3(h) => (*h).finalize().to_hex().to_string(),
                DynH::Sha256(h) => hex::encode(h.finalize()),
                DynH::Sha512(h) => hex::encode(h.finalize()),
                DynH::Sha3_256(h) => hex::encode(h.finalize()),
                DynH::Sha1(h) => hex::encode(h.finalize()),
                DynH::Md5(h) => hex::encode(h.finalize()),
                DynH::Tiger(h) => hex::encode(h.finalize()),
                DynH::Whirlpool(h) => hex::encode(h.finalize()),
            }
        }
    }

    fn make_dynh(algo: Algorithm) -> Result<DynH> {
        Ok(match algo {
            Algorithm::Blake3 => DynH::Blake3(Box::new(blake3::Hasher::new())),
            Algorithm::Sha256 => DynH::Sha256(Box::new(sha2::Sha256::new())),
            Algorithm::Sha512 => DynH::Sha512(Box::new(sha2::Sha512::new())),
            Algorithm::Sha3_256 => DynH::Sha3_256(Box::new(sha3::Sha3_256::new())),
            Algorithm::Sha1 => DynH::Sha1(Box::new(sha1::Sha1::new())),
            Algorithm::Md5 => DynH::Md5(Box::new(md5::Md5::new())),
            Algorithm::Tiger => DynH::Tiger(Box::new(tiger::Tiger::new())),
            Algorithm::Whirlpool => DynH::Whirlpool(Box::new(whirlpool::Whirlpool::new())),
            _ => anyhow::bail!("unsupported algorithm for device hashing: {algo}"),
        })
    }

    let mut hashers: Vec<(Algorithm, DynH)> = algorithms
        .iter()
        .map(|a| Ok((*a, make_dynh(*a)?)))
        .collect::<Result<Vec<_>>>()?;

    let mut total_bytes: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for (_, h) in &mut hashers {
            h.update(&buf[..n]);
        }
        total_bytes += n as u64;
    }

    let mut hashes = HashMap::new();
    for (algo, h) in hashers {
        hashes.insert(algo, h.finalize_hex());
    }

    Ok(FileHashResult {
        path: path.to_path_buf(),
        size: total_bytes,
        hashes,
        entropy: None,
        #[cfg(feature = "yara")]
        yara_matches: None,
    })
}
