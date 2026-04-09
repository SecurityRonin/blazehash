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

#[cfg(target_os = "linux")]
const DIRECT_IO_ALIGN: usize = 4096;
#[cfg(target_os = "linux")]
const DIRECT_IO_BUF_SIZE: usize = DIRECT_IO_ALIGN * 16; // 64 KiB, aligned

/// A heap-allocated buffer with 4096-byte alignment for O_DIRECT I/O.
/// `#[repr(align(4096))]` ensures Box<AlignedBuf> satisfies the kernel's
/// alignment requirements, and Box drops it with the correct Layout.
#[cfg(target_os = "linux")]
#[repr(align(4096))]
struct AlignedBuf([u8; DIRECT_IO_BUF_SIZE]);

#[cfg(target_os = "linux")]
fn open_file_direct_linux(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(path)
        .with_context(|| format!("failed to open {} with O_DIRECT", path.display()))
}

#[cfg(target_os = "linux")]
fn hash_file_direct_linux(path: &Path, algorithms: &[Algorithm]) -> Result<HashMap<Algorithm, String>> {
    use std::io::{Read, Seek, SeekFrom};

    let file_size = std::fs::metadata(path)?.len() as usize;
    let mut file = open_file_direct_linux(path)?;
    let mut buf = Box::new(AlignedBuf([0u8; DIRECT_IO_BUF_SIZE]));

    let mut hashers: Vec<(Algorithm, Box<dyn DynHasher>)> = algorithms
        .iter()
        .map(|algo| (*algo, make_hasher(*algo)))
        .collect();

    let mut total_read = 0usize;
    loop {
        let n = file.read(&mut buf.0)?;
        if n == 0 {
            break;
        }
        for (_, hasher) in &mut hashers {
            hasher.update(&buf.0[..n]);
        }
        total_read += n;
        // O_DIRECT stops reading at the last aligned block boundary
        if total_read >= (file_size / DIRECT_IO_ALIGN) * DIRECT_IO_ALIGN {
            break;
        }
    }

    // If the file has trailing bytes beyond the last aligned block, re-read
    // them without O_DIRECT (the kernel cannot return sub-sector remainders
    // via O_DIRECT).
    if total_read < file_size {
        let mut tail_file = std::fs::File::open(path)
            .with_context(|| format!("failed to open {} for tail read", path.display()))?;
        tail_file.seek(SeekFrom::Start(total_read as u64))?;
        let mut tail = Vec::new();
        tail_file.read_to_end(&mut tail)?;
        for (_, hasher) in &mut hashers {
            hasher.update(&tail);
        }
    }

    let mut hashes = HashMap::new();
    for (algo, hasher) in hashers {
        hashes.insert(algo, hasher.finalize_hex());
    }
    Ok(hashes)
}

/// Open a file, optionally advising the OS to bypass the page cache (macOS F_NOCACHE).
fn open_file_no_cache(path: &Path) -> Result<std::fs::File> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1i32) };
        if ret == -1 {
            eprintln!("[warn] fcntl(F_NOCACHE) failed, proceeding without cache bypass");
        }
    }

    Ok(file)
}

/// Hash a file with one or more algorithms simultaneously.
pub fn hash_file(path: &Path, algorithms: &[Algorithm], no_cache: bool) -> Result<FileHashResult> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    let size = metadata.len();

    let hashes = {
        #[cfg(target_os = "linux")]
        if no_cache {
            hash_file_direct_linux(path, algorithms)?
        } else if size >= MMAP_THRESHOLD {
            hash_file_mmap(path, algorithms, size, false)?
        } else {
            hash_file_streaming(path, algorithms, false)?
        }

        #[cfg(not(target_os = "linux"))]
        if size >= MMAP_THRESHOLD {
            hash_file_mmap(path, algorithms, size, no_cache)?
        } else {
            hash_file_streaming(path, algorithms, no_cache)?
        }
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
    no_cache: bool,
) -> Result<HashMap<Algorithm, String>> {
    let file = if no_cache {
        open_file_no_cache(path)?
    } else {
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?
    };
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
    no_cache: bool,
) -> Result<HashMap<Algorithm, String>> {
    let mut file = if no_cache {
        open_file_no_cache(path)?
    } else {
        fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?
    };
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
