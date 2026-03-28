use crate::algorithm::Algorithm;
use anyhow::{Context, Result};
use digest::Digest;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Result of hashing a single file.
#[derive(Debug)]
pub struct FileHashResult {
    pub path: PathBuf,
    pub size: u64,
    pub hashes: HashMap<Algorithm, String>,
}

/// Threshold above which we use memory-mapped I/O (1 MiB).
const MMAP_THRESHOLD: u64 = 1024 * 1024;

/// Hash a file with one or more algorithms simultaneously.
pub fn hash_file(path: &Path, algorithms: &[Algorithm]) -> Result<FileHashResult> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    let size = metadata.len();

    let hashes = if size >= MMAP_THRESHOLD {
        hash_file_mmap(path, algorithms, size)?
    } else {
        hash_file_streaming(path, algorithms)?
    };

    Ok(FileHashResult {
        path: path.to_path_buf(),
        size,
        hashes,
    })
}

fn hash_file_mmap(
    path: &Path,
    algorithms: &[Algorithm],
    _size: u64,
) -> Result<HashMap<Algorithm, String>> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let mmap = unsafe {
        memmap2::Mmap::map(&file)
            .with_context(|| format!("failed to memory-map {}", path.display()))?
    };
    let data = &mmap[..];

    let mut hashes = HashMap::new();
    for algo in algorithms {
        hashes.insert(*algo, crate::algorithm::hash_bytes(*algo, data));
    }
    Ok(hashes)
}

fn hash_file_streaming(
    path: &Path,
    algorithms: &[Algorithm],
) -> Result<HashMap<Algorithm, String>> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let mut buf = vec![0u8; 64 * 1024]; // 64 KiB read buffer

    // Build a hasher for each algorithm
    let mut hashers: Vec<(Algorithm, Box<dyn DynHasher>)> = algorithms
        .iter()
        .map(|algo| (*algo, make_hasher(*algo)))
        .collect();

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for (_, hasher) in &mut hashers {
            hasher.update(&buf[..n]);
        }
    }

    let mut hashes = HashMap::new();
    for (algo, hasher) in hashers {
        hashes.insert(algo, hasher.finalize_hex());
    }
    Ok(hashes)
}

trait DynHasher: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize_hex(self: Box<Self>) -> String;
}

struct DigestHasher<D: Digest> {
    inner: D,
}

impl<D: Digest + Send + 'static> DynHasher for DigestHasher<D> {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize_hex(self: Box<Self>) -> String {
        hex::encode(self.inner.finalize())
    }
}

struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl DynHasher for Blake3Hasher {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize_hex(self: Box<Self>) -> String {
        self.inner.finalize().to_hex().to_string()
    }
}

fn make_hasher(algo: Algorithm) -> Box<dyn DynHasher> {
    match algo {
        Algorithm::Blake3 => Box::new(Blake3Hasher {
            inner: blake3::Hasher::new(),
        }),
        Algorithm::Sha256 => Box::new(DigestHasher {
            inner: sha2::Sha256::new(),
        }),
        Algorithm::Sha512 => Box::new(DigestHasher {
            inner: sha2::Sha512::new(),
        }),
        Algorithm::Sha3_256 => Box::new(DigestHasher {
            inner: sha3::Sha3_256::new(),
        }),
        Algorithm::Sha1 => Box::new(DigestHasher {
            inner: sha1::Sha1::new(),
        }),
        Algorithm::Md5 => Box::new(DigestHasher {
            inner: md5::Md5::new(),
        }),
        Algorithm::Tiger => Box::new(DigestHasher {
            inner: tiger::Tiger::new(),
        }),
        Algorithm::Whirlpool => Box::new(DigestHasher {
            inner: whirlpool::Whirlpool::new(),
        }),
    }
}
