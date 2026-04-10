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

/// Threshold above which we hint the kernel to use transparent huge pages (2 MiB).
#[cfg(target_os = "linux")]
const LARGE_PAGE_THRESHOLD: usize = 2 * 1024 * 1024;

#[cfg(any(target_os = "linux", target_os = "windows"))]
const DIRECT_IO_ALIGN: usize = 4096;
#[cfg(any(target_os = "linux", target_os = "windows"))]
const DIRECT_IO_BUF_SIZE: usize = DIRECT_IO_ALIGN * 16; // 64 KiB, aligned

/// A heap-allocated buffer with 4096-byte alignment for O_DIRECT / FILE_FLAG_NO_BUFFERING I/O.
/// `#[repr(align(4096))]` ensures Box<AlignedBuf> satisfies the kernel's
/// alignment requirements, and Box drops it with the correct Layout.
#[cfg(any(target_os = "linux", target_os = "windows"))]
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
fn hash_file_direct_linux(
    path: &Path,
    algorithms: &[Algorithm],
) -> Result<HashMap<Algorithm, String>> {
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

#[cfg(target_os = "windows")]
fn try_alloc_large_page_buf(size: usize) -> Option<*mut u8> {
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_LARGE_PAGES, MEM_RESERVE, PAGE_READWRITE,
    };
    let ptr = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            size,
            MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
            PAGE_READWRITE,
        )
    };
    if ptr.is_null() {
        None
    } else {
        Some(ptr as *mut u8)
    }
}

#[cfg(target_os = "windows")]
fn free_large_page_buf(ptr: *mut u8, _size: usize) {
    use windows_sys::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
    unsafe {
        VirtualFree(ptr as *mut _, 0, MEM_RELEASE);
    }
}

#[cfg(target_os = "windows")]
fn open_file_direct_windows(path: &Path) -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_NO_BUFFERING, FILE_FLAG_SEQUENTIAL_SCAN,
    };

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
        .with_context(|| {
            format!(
                "failed to open {} with FILE_FLAG_NO_BUFFERING",
                path.display()
            )
        })
}

#[cfg(target_os = "windows")]
fn hash_file_direct_windows(
    path: &Path,
    algorithms: &[Algorithm],
) -> Result<HashMap<Algorithm, String>> {
    use std::io::{Read, Seek, SeekFrom};

    let file_size = std::fs::metadata(path)?.len() as usize;
    let mut file = open_file_direct_windows(path)?;

    // Attempt MEM_LARGE_PAGES allocation; silently fall back to normal aligned heap if unavailable.
    let large_page_ptr = try_alloc_large_page_buf(DIRECT_IO_BUF_SIZE);
    let mut fallback_buf = if large_page_ptr.is_none() {
        Some(Box::new(AlignedBuf([0u8; DIRECT_IO_BUF_SIZE])))
    } else {
        None
    };

    let buf_slice: &mut [u8] = if let Some(ptr) = large_page_ptr {
        unsafe { std::slice::from_raw_parts_mut(ptr, DIRECT_IO_BUF_SIZE) }
    } else {
        &mut fallback_buf.as_mut().unwrap().0
    };

    let mut hashers: Vec<(Algorithm, Box<dyn DynHasher>)> = algorithms
        .iter()
        .map(|algo| (*algo, make_hasher(*algo)))
        .collect();

    let mut total_read = 0usize;
    loop {
        let n = file.read(buf_slice)?;
        if n == 0 {
            break;
        }
        for (_, hasher) in &mut hashers {
            hasher.update(&buf_slice[..n]);
        }
        total_read += n;
        // FILE_FLAG_NO_BUFFERING stops reading at the last aligned block boundary
        if total_read >= (file_size / DIRECT_IO_ALIGN) * DIRECT_IO_ALIGN {
            break;
        }
    }

    // Free large page buffer before the tail read to avoid holding it longer than needed.
    if let Some(ptr) = large_page_ptr {
        // SAFETY: buf_slice is not accessed after this point — the tail read uses tail_file, not buf_slice.
        free_large_page_buf(ptr, DIRECT_IO_BUF_SIZE);
    }

    // Handle trailing bytes beyond the last aligned block — re-read without
    // FILE_FLAG_NO_BUFFERING (the driver cannot return sub-sector remainders).
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
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;

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
///
/// `no_gpu`: when true, skip GPU acceleration even if available (pass `false`
/// for callers that don't expose this flag — GPU is already gated by feature flag).
pub fn hash_file(
    path: &Path,
    algorithms: &[Algorithm],
    no_cache: bool,
    no_gpu: bool,
) -> Result<FileHashResult> {
    // no_gpu is only consumed by the gpu feature block below; suppress the warning otherwise.
    #[cfg(not(feature = "gpu"))]
    let _ = no_gpu;
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    let size = metadata.len();

    // Separate crypto, fuzzy, and non-cryptographic algorithms.
    // Fuzzy and non-crypto hashes are computed separately after via hash_bytes;
    // only pure crypto algorithms flow through make_hasher.
    let fuzzy_algorithms: Vec<Algorithm> = algorithms
        .iter()
        .filter(|a| a.is_fuzzy())
        .copied()
        .collect();
    let full_read_algorithms: Vec<Algorithm> = algorithms
        .iter()
        .filter(|a| a.needs_full_read())
        .copied()
        .collect();
    let crypto_algorithms: Vec<Algorithm> = algorithms
        .iter()
        .filter(|a| !a.is_fuzzy() && !a.needs_full_read())
        .copied()
        .collect();
    let algorithms = &crypto_algorithms; // shadow: rest of function uses crypto-only slice

    let mut hashes = {
        #[cfg(target_os = "linux")]
        if no_cache {
            hash_file_direct_linux(path, algorithms)?
        } else if size >= MMAP_THRESHOLD {
            hash_file_mmap(path, algorithms, size, false)?
        } else {
            hash_file_streaming(path, algorithms, false)?
        }

        #[cfg(target_os = "windows")]
        if no_cache {
            hash_file_direct_windows(path, algorithms)?
        } else if size >= MMAP_THRESHOLD {
            hash_file_mmap(path, algorithms, size, no_cache)?
        } else {
            hash_file_streaming(path, algorithms, no_cache)?
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        if size >= MMAP_THRESHOLD {
            hash_file_mmap(path, algorithms, size, no_cache)?
        } else {
            hash_file_streaming(path, algorithms, no_cache)?
        }
    };

    // GPU override: replace CPU hashes with GPU hashes for eligible algorithms.
    // Only active when the `gpu` feature is enabled and `no_gpu` is false.
    #[cfg(feature = "gpu")]
    if !no_gpu {
        if let Some(gpu_hashes) = try_gpu_hash(path, algorithms) {
            for (algo, hash) in gpu_hashes {
                hashes.insert(algo, hash);
            }
        }
    }

    // Fuzzy pass: ssdeep/tlsh require full file bytes; read separately from crypto path.
    if !fuzzy_algorithms.is_empty() {
        let data = fs::read(path)
            .with_context(|| format!("failed to read {} for fuzzy hashing", path.display()))?;
        let fuzzy_hashes = crate::fuzzy::compute_fuzzy(&data, &fuzzy_algorithms);
        hashes.extend(fuzzy_hashes);
    }

    // Full-read pass: crc32c/xxh3 (non-crypto) and shake128/shake256 (XOF) use hash_bytes
    // rather than the streaming DynHasher trait; read full file bytes if needed.
    if !full_read_algorithms.is_empty() {
        let data = fs::read(path).with_context(|| {
            format!(
                "failed to read {} for full-read hashing",
                path.display()
            )
        })?;
        for algo in &full_read_algorithms {
            hashes.insert(*algo, crate::algorithm::hash_bytes(*algo, &data));
        }
    }

    Ok(FileHashResult {
        path: path.to_path_buf(),
        size,
        hashes,
    })
}


/// Attempt to hash GPU-eligible algorithms (SHA-256, MD5) on the GPU.
/// Returns None if no GPU is available, thresholds are not met, or GPU is
/// in NeedsCalibration state. Returns Some(map) with only the GPU-computed
/// hashes — the caller merges them over the CPU results.
#[cfg(feature = "gpu")]
fn try_gpu_hash(path: &Path, algorithms: &[Algorithm]) -> Option<HashMap<Algorithm, String>> {
    use crate::gpu::{
        backend::GpuBackend,
        config::GpuConfigState,
        md5::GpuMd5,
        sha256::GpuSha256,
        threshold::{should_use_gpu, GPU_ALGOS},
    };

    let config_path = crate::config::config_path();
    let config = crate::config::BlazeConfig::load(&config_path).gpu;
    let backend = GpuBackend::detect()?;
    let adapter_name = backend.adapter_name().to_string();

    let state = GpuConfigState::resolve(config, Some(&adapter_name), &config_path);

    let file_size_mb = std::fs::metadata(path).ok()?.len() / (1024 * 1024);
    if !should_use_gpu(file_size_mb, algorithms, &state) {
        return None;
    }

    // Read the file once; upload to GPU for each eligible algorithm.
    let data = std::fs::read(path).ok()?;

    let mut results = HashMap::new();
    for algo in algorithms {
        if !GPU_ALGOS.contains(algo) {
            continue;
        }
        let hash = match algo {
            Algorithm::Sha256 => GpuSha256::new(&backend).hash(&data),
            Algorithm::Md5 => GpuMd5::new(&backend).hash(&data),
            _ => continue,
        };
        results.insert(*algo, hash);
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
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

    // Hint kernel to use transparent huge pages for large mappings (Linux only)
    #[cfg(target_os = "linux")]
    {
        if mmap.len() >= LARGE_PAGE_THRESHOLD {
            unsafe {
                libc::madvise(
                    mmap.as_ptr() as *mut libc::c_void,
                    mmap.len(),
                    libc::MADV_HUGEPAGE,
                );
                // Return value ignored — advisory hint, not guaranteed
            }
        }
    }

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
        Algorithm::Ssdeep | Algorithm::Tlsh => {
            panic!("fuzzy algorithms (ssdeep/tlsh) cannot be used via make_hasher; use crate::fuzzy::compute_fuzzy instead")
        }
        Algorithm::Crc32c | Algorithm::Xxh3 => {
            panic!("non-cryptographic algorithms (crc32c/xxh3) cannot be used via make_hasher; use algorithm::hash_bytes instead")
        }
        Algorithm::Shake128 | Algorithm::Shake256 => {
            panic!("XOF algorithms (shake128/shake256) cannot be used via make_hasher; use algorithm::hash_bytes instead")
        }
    }
}
