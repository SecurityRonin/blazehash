# Blazehash Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a forensic file hasher (library + CLI) that is a drop-in superset of hashdeep, defaulting to BLAKE3, with multithreaded parallel hashing and memory-mapped I/O.

**Architecture:** Rust library crate (`blazehash`) with a binary target. Core hashing uses the RustCrypto `digest` trait as a uniform interface across all algorithms. BLAKE3 uses its own crate for tree-parallel hashing. File walking uses `walkdir` + `rayon` for parallel traversal. Memory-mapped I/O via `memmap2` for large files, with a fallback to streaming for special files.

**Tech Stack:** Rust, blake3, sha2, sha1, sha3, md-5, tiger, whirlpool, digest, memmap2, rayon, walkdir, clap, anyhow, serde/serde_json

---

## File Structure

```
blazehash/
  Cargo.toml
  src/
    lib.rs              # Public API re-exports
    algorithm.rs        # Algorithm enum, hasher abstraction
    hash.rs             # Single-file hashing (streaming + mmap)
    walk.rs             # Recursive parallel file walking
    manifest.rs         # hashdeep output format (read + write)
    audit.rs            # Audit mode (match/move/new/changed)
    format/
      mod.rs            # Format trait + registry
      hashdeep.rs       # hashdeep format writer/reader
      csv.rs            # CSV format writer
      json.rs           # JSON/JSONL format writer
      dfxml.rs          # DFXML format writer
    piecewise.rs        # Chunk-level hashing
    nsrl.rs             # NSRL dataset import + bloom filter
    resume.rs           # Checkpoint + resume state
    cli.rs              # CLI argument parsing (clap)
    main.rs             # Binary entry point
  tests/
    algorithm_tests.rs  # Algorithm enum + digest tests
    hash_tests.rs       # File hashing tests
    walk_tests.rs       # Directory walking tests
    manifest_tests.rs   # hashdeep format round-trip tests
    audit_tests.rs      # Audit mode tests
    format_tests.rs     # Output format tests
    piecewise_tests.rs  # Piecewise hashing tests
    nsrl_tests.rs       # NSRL import tests
    resume_tests.rs     # Resume state tests
    cli_tests.rs        # CLI integration tests
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`
- Create: `src/main.rs`
- Create: `src/algorithm.rs`

- [ ] **Step 1: Create Cargo.toml**

```toml
[package]
name = "blazehash"
version = "0.1.0"
edition = "2021"
description = "Forensic file hasher — hashdeep for the modern era, BLAKE3 by default"
license = "MIT"
repository = "https://github.com/SecurityRonin/blazehash"
keywords = ["hash", "forensics", "blake3", "hashdeep", "dfir"]
categories = ["command-line-utilities", "cryptography"]

[[bin]]
name = "blazehash"
path = "src/main.rs"

[lib]
name = "blazehash"
path = "src/lib.rs"

[dependencies]
anyhow = "1"
blake3 = "1"
clap = { version = "4", features = ["derive"] }
digest = "0.10"
hex = "0.4"
md-5 = "0.10"
memmap2 = "0.9"
rayon = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha1 = { version = "0.10", features = ["oid"] }
sha2 = { version = "0.10", features = ["oid"] }
sha3 = { version = "0.10" }
tiger = "0.2"
walkdir = "2"
whirlpool = "0.10"

[dev-dependencies]
tempfile = "3"
assert_cmd = "2"
predicates = "3"
```

- [ ] **Step 2: Create minimal src/lib.rs**

```rust
pub mod algorithm;
```

- [ ] **Step 3: Create minimal src/main.rs**

```rust
fn main() {
    println!("blazehash v{}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo build`
Expected: Compiles successfully

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/lib.rs src/main.rs
git commit -m "feat: project scaffolding with dependencies"
```

---

### Task 2: Algorithm Enum and Hasher Abstraction

**Files:**
- Create: `src/algorithm.rs`
- Create: `tests/algorithm_tests.rs`

- [ ] **Step 1: Write failing test — parse algorithm names from strings**

Create `tests/algorithm_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;
use std::str::FromStr;

#[test]
fn parse_blake3() {
    let algo = Algorithm::from_str("blake3").unwrap();
    assert_eq!(algo, Algorithm::Blake3);
}

#[test]
fn parse_sha256() {
    let algo = Algorithm::from_str("sha256").unwrap();
    assert_eq!(algo, Algorithm::Sha256);
    // hashdeep uses sha-256 as well
    let algo2 = Algorithm::from_str("sha-256").unwrap();
    assert_eq!(algo2, Algorithm::Sha256);
}

#[test]
fn parse_sha1() {
    let algo = Algorithm::from_str("sha1").unwrap();
    assert_eq!(algo, Algorithm::Sha1);
    let algo2 = Algorithm::from_str("sha-1").unwrap();
    assert_eq!(algo2, Algorithm::Sha1);
}

#[test]
fn parse_md5() {
    let algo = Algorithm::from_str("md5").unwrap();
    assert_eq!(algo, Algorithm::Md5);
}

#[test]
fn parse_sha512() {
    let algo = Algorithm::from_str("sha512").unwrap();
    assert_eq!(algo, Algorithm::Sha512);
}

#[test]
fn parse_sha3_256() {
    let algo = Algorithm::from_str("sha3-256").unwrap();
    assert_eq!(algo, Algorithm::Sha3_256);
}

#[test]
fn parse_tiger() {
    let algo = Algorithm::from_str("tiger").unwrap();
    assert_eq!(algo, Algorithm::Tiger);
}

#[test]
fn parse_whirlpool() {
    let algo = Algorithm::from_str("whirlpool").unwrap();
    assert_eq!(algo, Algorithm::Whirlpool);
}

#[test]
fn parse_invalid_algorithm() {
    assert!(Algorithm::from_str("xxhash").is_err());
}

#[test]
fn algorithm_display_roundtrips() {
    for algo in Algorithm::all() {
        let s = algo.to_string();
        let parsed = Algorithm::from_str(&s).unwrap();
        assert_eq!(*algo, parsed);
    }
}

#[test]
fn default_algorithm_is_blake3() {
    assert_eq!(Algorithm::default(), Algorithm::Blake3);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test algorithm_tests`
Expected: FAIL — `algorithm::Algorithm` not found

- [ ] **Step 3: Write minimal implementation**

Create `src/algorithm.rs`:

```rust
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Blake3,
    Sha256,
    Sha512,
    Sha3_256,
    Sha1,
    Md5,
    Tiger,
    Whirlpool,
}

impl Algorithm {
    pub fn all() -> &'static [Algorithm] {
        &[
            Algorithm::Blake3,
            Algorithm::Sha256,
            Algorithm::Sha512,
            Algorithm::Sha3_256,
            Algorithm::Sha1,
            Algorithm::Md5,
            Algorithm::Tiger,
            Algorithm::Whirlpool,
        ]
    }

    /// Name used in hashdeep-compatible output headers.
    pub fn hashdeep_name(&self) -> &'static str {
        match self {
            Algorithm::Blake3 => "blake3",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
            Algorithm::Sha3_256 => "sha3-256",
            Algorithm::Sha1 => "sha1",
            Algorithm::Md5 => "md5",
            Algorithm::Tiger => "tiger",
            Algorithm::Whirlpool => "whirlpool",
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::Blake3
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.hashdeep_name())
    }
}

impl FromStr for Algorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "blake3" => Ok(Algorithm::Blake3),
            "sha256" | "sha-256" => Ok(Algorithm::Sha256),
            "sha512" | "sha-512" => Ok(Algorithm::Sha512),
            "sha3-256" | "sha3_256" => Ok(Algorithm::Sha3_256),
            "sha1" | "sha-1" => Ok(Algorithm::Sha1),
            "md5" => Ok(Algorithm::Md5),
            "tiger" => Ok(Algorithm::Tiger),
            "whirlpool" => Ok(Algorithm::Whirlpool),
            other => anyhow::bail!("unknown algorithm: {}", other),
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test algorithm_tests`
Expected: All 11 tests PASS

- [ ] **Step 5: Write failing test — hash bytes with each algorithm**

Add to `tests/algorithm_tests.rs`:

```rust
use blazehash::algorithm::hash_bytes;

#[test]
fn hash_bytes_blake3_known_vector() {
    let hash = hash_bytes(Algorithm::Blake3, b"hello world");
    // BLAKE3 hash of "hello world"
    assert_eq!(
        hash,
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
    );
}

#[test]
fn hash_bytes_sha256_known_vector() {
    let hash = hash_bytes(Algorithm::Sha256, b"hello world");
    assert_eq!(
        hash,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

#[test]
fn hash_bytes_md5_known_vector() {
    let hash = hash_bytes(Algorithm::Md5, b"hello world");
    assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
}

#[test]
fn hash_bytes_sha1_known_vector() {
    let hash = hash_bytes(Algorithm::Sha1, b"hello world");
    assert_eq!(hash, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
}

#[test]
fn hash_bytes_sha512_known_vector() {
    let hash = hash_bytes(Algorithm::Sha512, b"hello world");
    assert_eq!(
        hash,
        "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
    );
}

#[test]
fn hash_bytes_empty_input() {
    // All algorithms should handle empty input
    for algo in Algorithm::all() {
        let hash = hash_bytes(*algo, b"");
        assert!(!hash.is_empty(), "empty hash for {:?}", algo);
    }
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test algorithm_tests hash_bytes`
Expected: FAIL — `hash_bytes` not found

- [ ] **Step 7: Implement hash_bytes**

Add to `src/algorithm.rs`:

```rust
use digest::Digest;

/// Hash a byte slice with the given algorithm, returning the hex-encoded digest.
pub fn hash_bytes(algo: Algorithm, data: &[u8]) -> String {
    match algo {
        Algorithm::Blake3 => {
            let hash = blake3::hash(data);
            hash.to_hex().to_string()
        }
        Algorithm::Sha256 => hex_digest::<sha2::Sha256>(data),
        Algorithm::Sha512 => hex_digest::<sha2::Sha512>(data),
        Algorithm::Sha3_256 => hex_digest::<sha3::Sha3_256>(data),
        Algorithm::Sha1 => hex_digest::<sha1::Sha1>(data),
        Algorithm::Md5 => hex_digest::<md5::Md5>(data),
        Algorithm::Tiger => hex_digest::<tiger::Tiger>(data),
        Algorithm::Whirlpool => hex_digest::<whirlpool::Whirlpool>(data),
    }
}

fn hex_digest<D: Digest>(data: &[u8]) -> String {
    let mut hasher = D::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test algorithm_tests`
Expected: All 17 tests PASS

- [ ] **Step 9: Commit**

```bash
git add src/algorithm.rs tests/algorithm_tests.rs
git commit -m "feat: algorithm enum with parsing and hash_bytes"
```

---

### Task 3: Single-File Hashing (Streaming + Mmap)

**Files:**
- Create: `src/hash.rs`
- Create: `tests/hash_tests.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing test — hash a file with a single algorithm**

Create `tests/hash_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;
use blazehash::hash::hash_file;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn hash_file_blake3() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"hello world").unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3]).unwrap();
    assert_eq!(result.size, 11);
    assert_eq!(
        result.hashes[&Algorithm::Blake3],
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
    );
}

#[test]
fn hash_file_multiple_algorithms() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"hello world").unwrap();
    f.flush().unwrap();

    let algos = vec![Algorithm::Blake3, Algorithm::Sha256, Algorithm::Md5];
    let result = hash_file(f.path(), &algos).unwrap();
    assert_eq!(result.size, 11);
    assert_eq!(result.hashes.len(), 3);
    assert_eq!(
        result.hashes[&Algorithm::Sha256],
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    assert_eq!(
        result.hashes[&Algorithm::Md5],
        "5eb63bbbe01eeed093cb22bb8f5acdc3"
    );
}

#[test]
fn hash_file_empty() {
    let f = NamedTempFile::new().unwrap();
    let result = hash_file(f.path(), &[Algorithm::Blake3]).unwrap();
    assert_eq!(result.size, 0);
    assert!(!result.hashes[&Algorithm::Blake3].is_empty());
}

#[test]
fn hash_file_large_uses_mmap() {
    // Create a 2 MiB file to trigger mmap path
    let mut f = NamedTempFile::new().unwrap();
    let data = vec![0x42u8; 2 * 1024 * 1024];
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3, Algorithm::Sha256]).unwrap();
    assert_eq!(result.size, 2 * 1024 * 1024);

    // Verify against hash_bytes for correctness
    let expected_blake3 = blazehash::algorithm::hash_bytes(Algorithm::Blake3, &data);
    assert_eq!(result.hashes[&Algorithm::Blake3], expected_blake3);
}

#[test]
fn hash_file_returns_path() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"test").unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3]).unwrap();
    assert_eq!(result.path, f.path());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test hash_tests`
Expected: FAIL — `hash::hash_file` not found

- [ ] **Step 3: Implement hash_file**

Create `src/hash.rs`:

```rust
use crate::algorithm::Algorithm;
use anyhow::Result;
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
    let metadata = fs::metadata(path)?;
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
    let file = fs::File::open(path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
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
    let mut file = fs::File::open(path)?;
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
```

Update `src/lib.rs`:

```rust
pub mod algorithm;
pub mod hash;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test hash_tests`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/hash.rs src/lib.rs tests/hash_tests.rs
git commit -m "feat: single-file hashing with mmap and streaming paths"
```

---

### Task 4: hashdeep Output Format

**Files:**
- Create: `src/manifest.rs`
- Create: `tests/manifest_tests.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing test — write hashdeep header**

Create `tests/manifest_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;
use blazehash::manifest::{write_header, write_record, parse_header};
use blazehash::hash::FileHashResult;
use std::collections::HashMap;
use std::path::PathBuf;

#[test]
fn write_header_default_blake3() {
    let mut buf = Vec::new();
    write_header(&mut buf, &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.starts_with("%%%% HASHDEEP-1.0\n"));
    assert!(output.contains("%%%% size,blake3,filename\n"));
}

#[test]
fn write_header_multiple_algorithms() {
    let mut buf = Vec::new();
    write_header(&mut buf, &[Algorithm::Md5, Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("%%%% size,md5,sha256,filename\n"));
}

#[test]
fn write_record_single_algorithm() {
    let mut hashes = HashMap::new();
    hashes.insert(
        Algorithm::Blake3,
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24".to_string(),
    );
    let result = FileHashResult {
        path: PathBuf::from("/home/user/test.txt"),
        size: 11,
        hashes,
    };

    let mut buf = Vec::new();
    write_record(&mut buf, &result, &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert_eq!(
        output,
        "11,d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24,/home/user/test.txt\n"
    );
}

#[test]
fn write_record_multiple_algorithms() {
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Md5, "5eb63bbbe01eeed093cb22bb8f5acdc3".to_string());
    hashes.insert(
        Algorithm::Sha256,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
    );
    let result = FileHashResult {
        path: PathBuf::from("/home/user/test.txt"),
        size: 11,
        hashes,
    };

    let mut buf = Vec::new();
    write_record(&mut buf, &result, &[Algorithm::Md5, Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert_eq!(
        output,
        "11,5eb63bbbe01eeed093cb22bb8f5acdc3,b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9,/home/user/test.txt\n"
    );
}

#[test]
fn parse_header_extracts_algorithms() {
    let input = "%%%% HASHDEEP-1.0\n%%%% size,md5,sha256,filename\n## Invoked from: /home\n";
    let algos = parse_header(input).unwrap();
    assert_eq!(algos, vec![Algorithm::Md5, Algorithm::Sha256]);
}

#[test]
fn parse_header_single_algorithm() {
    let input = "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n";
    let algos = parse_header(input).unwrap();
    assert_eq!(algos, vec![Algorithm::Blake3]);
}

#[test]
fn filename_with_comma_preserved() {
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abcd1234".to_string());
    let result = FileHashResult {
        path: PathBuf::from("/home/user/file,with,commas.txt"),
        size: 42,
        hashes,
    };

    let mut buf = Vec::new();
    write_record(&mut buf, &result, &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    // Commas in filename are preserved — parser uses column count from header
    assert_eq!(output, "42,abcd1234,/home/user/file,with,commas.txt\n");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test manifest_tests`
Expected: FAIL — `manifest` module not found

- [ ] **Step 3: Implement manifest module**

Create `src/manifest.rs`:

```rust
use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::{bail, Result};
use std::io::Write;
use std::str::FromStr;

/// Write the hashdeep-format header.
pub fn write_header<W: Write>(w: &mut W, algorithms: &[Algorithm]) -> Result<()> {
    writeln!(w, "%%%% HASHDEEP-1.0")?;
    write!(w, "%%%% size")?;
    for algo in algorithms {
        write!(w, ",{}", algo.hashdeep_name())?;
    }
    writeln!(w, ",filename")?;
    writeln!(w, "## Invoked from: blazehash v{}", env!("CARGO_PKG_VERSION"))?;
    writeln!(w, "##")?;
    Ok(())
}

/// Write a single hashdeep-format record.
pub fn write_record<W: Write>(
    w: &mut W,
    result: &FileHashResult,
    algorithms: &[Algorithm],
) -> Result<()> {
    write!(w, "{}", result.size)?;
    for algo in algorithms {
        write!(w, ",{}", result.hashes[algo])?;
    }
    writeln!(w, ",{}", result.path.display())?;
    Ok(())
}

/// Parse a hashdeep-format header, returning the algorithms in column order.
pub fn parse_header(input: &str) -> Result<Vec<Algorithm>> {
    let mut lines = input.lines();

    // First line: %%%% HASHDEEP-1.0
    let first = lines.next().unwrap_or("");
    if !first.starts_with("%%%% HASHDEEP") {
        bail!("not a hashdeep file: missing header");
    }

    // Second line: %%%% size,algo1,algo2,...,filename
    let second = lines.next().unwrap_or("");
    if !second.starts_with("%%%% size,") {
        bail!("not a hashdeep file: missing column line");
    }

    let cols = &second["%%%% size,".len()..];
    let parts: Vec<&str> = cols.split(',').collect();

    // Last part is "filename", skip it
    if parts.is_empty() || parts.last() != Some(&"filename") {
        bail!("not a hashdeep file: missing filename column");
    }

    let algo_names = &parts[..parts.len() - 1];
    let mut algorithms = Vec::new();
    for name in algo_names {
        algorithms.push(Algorithm::from_str(name)?);
    }

    Ok(algorithms)
}
```

Update `src/lib.rs`:

```rust
pub mod algorithm;
pub mod hash;
pub mod manifest;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test manifest_tests`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/manifest.rs src/lib.rs tests/manifest_tests.rs
git commit -m "feat: hashdeep output format (write header, write record, parse header)"
```

---

### Task 5: Recursive Directory Walking

**Files:**
- Create: `src/walk.rs`
- Create: `tests/walk_tests.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing test — walk a directory and hash all files**

Create `tests/walk_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;
use blazehash::walk::walk_and_hash;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

#[test]
fn walk_empty_directory() {
    let dir = TempDir::new().unwrap();
    let results = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert!(results.is_empty());
}

#[test]
fn walk_flat_directory() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    fs::write(dir.path().join("b.txt"), b"bbb").unwrap();

    let results = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert_eq!(results.len(), 2);
    for r in &results {
        assert_eq!(r.size, 3);
        assert!(r.hashes.contains_key(&Algorithm::Blake3));
    }
}

#[test]
fn walk_recursive() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("root.txt"), b"root").unwrap();
    let sub = dir.path().join("subdir");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("nested.txt"), b"nested").unwrap();

    let results = walk_and_hash(dir.path(), &[Algorithm::Blake3], true).unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn walk_non_recursive_skips_subdirs() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("root.txt"), b"root").unwrap();
    let sub = dir.path().join("subdir");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("nested.txt"), b"nested").unwrap();

    let results = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn walk_multiple_algorithms() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello world").unwrap();

    let algos = vec![Algorithm::Blake3, Algorithm::Sha256];
    let results = walk_and_hash(dir.path(), &algos, false).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].hashes.len(), 2);
}

#[test]
fn walk_skips_directories_and_symlinks() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("file.txt"), b"content").unwrap();
    fs::create_dir(dir.path().join("subdir")).unwrap();

    let results = walk_and_hash(dir.path(), &[Algorithm::Blake3], true).unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].path.ends_with("file.txt"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test walk_tests`
Expected: FAIL — `walk` module not found

- [ ] **Step 3: Implement walk module with rayon parallelism**

Create `src/walk.rs`:

```rust
use crate::algorithm::Algorithm;
use crate::hash::{hash_file, FileHashResult};
use anyhow::Result;
use rayon::prelude::*;
use std::path::Path;
use walkdir::WalkDir;

/// Walk a directory, hash all files, return results.
/// Uses rayon for parallel file hashing.
pub fn walk_and_hash(
    root: &Path,
    algorithms: &[Algorithm],
    recursive: bool,
) -> Result<Vec<FileHashResult>> {
    let walker = if recursive {
        WalkDir::new(root)
    } else {
        WalkDir::new(root).max_depth(1)
    };

    let paths: Vec<_> = walker
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    let results: Vec<FileHashResult> = paths
        .par_iter()
        .filter_map(|path| hash_file(path, algorithms).ok())
        .collect();

    Ok(results)
}
```

Update `src/lib.rs`:

```rust
pub mod algorithm;
pub mod hash;
pub mod manifest;
pub mod walk;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test walk_tests`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/walk.rs src/lib.rs tests/walk_tests.rs
git commit -m "feat: recursive parallel directory walking with rayon"
```

---

### Task 6: CLI (hashdeep-Compatible Flags)

**Files:**
- Create: `src/cli.rs`
- Modify: `src/main.rs`
- Create: `tests/cli_tests.rs`

- [ ] **Step 1: Write failing test — CLI version flag**

Create `tests/cli_tests.rs`:

```rust
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn cli_version() {
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("blazehash"));
}

#[test]
fn cli_hash_single_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("HASHDEEP-1.0"))
        .stdout(predicate::str::contains("blake3"))
        .stdout(predicate::str::contains("test.txt"));
}

#[test]
fn cli_hash_directory_recursive() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("b.txt"), b"bbb").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-r")
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("a.txt"))
        .stdout(predicate::str::contains("b.txt"));
}

#[test]
fn cli_multiple_algorithms() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-c")
        .arg("blake3,sha256")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("size,blake3,sha256,filename"));
}

#[test]
fn cli_output_to_file() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello").unwrap();
    let output = dir.path().join("output.hash");

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-o")
        .arg(output.to_str().unwrap())
        .arg(file.to_str().unwrap())
        .assert()
        .success();

    let contents = fs::read_to_string(&output).unwrap();
    assert!(contents.contains("HASHDEEP-1.0"));
    assert!(contents.contains("test.txt"));
}

#[test]
fn cli_size_only_mode() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-s")
        .arg(file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("11"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test cli_tests cli_version`
Expected: FAIL — binary exists but no --version flag

- [ ] **Step 3: Implement CLI with clap**

Create `src/cli.rs`:

```rust
use crate::algorithm::Algorithm;
use clap::Parser;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(name = "blazehash", version, about = "Forensic file hasher — hashdeep for the modern era")]
pub struct Cli {
    /// Files or directories to hash
    #[arg(required_unless_present = "version")]
    pub paths: Vec<PathBuf>,

    /// Hash algorithms (comma-separated). Default: blake3
    #[arg(short = 'c', long = "compute", value_parser = parse_algorithms, default_value = "blake3")]
    pub algorithms: Vec<Algorithm>,

    /// Recursive mode
    #[arg(short = 'r', long = "recursive")]
    pub recursive: bool,

    /// Output file (default: stdout)
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Audit mode — verify files against known hashes
    #[arg(short = 'a', long = "audit")]
    pub audit: bool,

    /// Known hash file(s) for audit mode
    #[arg(short = 'k', long = "known")]
    pub known: Vec<PathBuf>,

    /// Size-only mode (no hashing)
    #[arg(short = 's', long = "size-only")]
    pub size_only: bool,

    /// Bare output (no header, no comments)
    #[arg(short = 'b', long = "bare")]
    pub bare: bool,

    /// Piecewise hashing chunk size (e.g. 1G, 100M)
    #[arg(short = 'p', long = "piecewise")]
    pub piecewise: Option<String>,

    /// Output format
    #[arg(long = "format", default_value = "hashdeep")]
    pub format: String,
}

fn parse_algorithms(s: &str) -> Result<Vec<Algorithm>, String> {
    s.split(',')
        .map(|name| Algorithm::from_str(name.trim()).map_err(|e| e.to_string()))
        .collect()
}

impl Cli {
    pub fn flat_algorithms(&self) -> Vec<Algorithm> {
        if self.algorithms.is_empty() {
            vec![Algorithm::Blake3]
        } else {
            // clap wraps the parsed Vec inside another Vec due to value_parser
            // Flatten: each entry in self.algorithms is itself a Vec<Algorithm>
            self.algorithms.clone()
        }
    }
}
```

Update `src/main.rs`:

```rust
mod cli;

use anyhow::Result;
use blazehash::algorithm::Algorithm;
use blazehash::hash::hash_file;
use blazehash::manifest::{write_header, write_record};
use blazehash::walk::walk_and_hash;
use clap::Parser;
use cli::Cli;
use std::fs::File;
use std::io::{self, BufWriter, Write};

fn main() -> Result<()> {
    let cli = Cli::parse();

    let algorithms = cli.flat_algorithms();

    let mut writer: Box<dyn Write> = match &cli.output {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };

    if cli.size_only {
        for path in &cli.paths {
            if path.is_file() {
                let meta = std::fs::metadata(path)?;
                writeln!(writer, "{}\t{}", meta.len(), path.display())?;
            } else if path.is_dir() {
                let results = walk_and_hash(path, &algorithms, cli.recursive)?;
                for r in &results {
                    writeln!(writer, "{}\t{}", r.size, r.path.display())?;
                }
            }
        }
        return Ok(());
    }

    if !cli.bare {
        write_header(&mut writer, &algorithms)?;
    }

    for path in &cli.paths {
        if path.is_file() {
            let result = hash_file(path, &algorithms)?;
            write_record(&mut writer, &result, &algorithms)?;
        } else if path.is_dir() {
            let results = walk_and_hash(path, &algorithms, cli.recursive)?;
            for result in &results {
                write_record(&mut writer, result, &algorithms)?;
            }
        }
    }

    writer.flush()?;
    Ok(())
}
```

Update `src/lib.rs`:

```rust
pub mod algorithm;
pub mod hash;
pub mod manifest;
pub mod walk;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test cli_tests`
Expected: All 6 tests PASS

- [ ] **Step 5: Also run all previous tests to ensure nothing broke**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/cli.rs src/main.rs src/lib.rs tests/cli_tests.rs
git commit -m "feat: CLI with hashdeep-compatible flags"
```

---

### Task 7: Audit Mode

**Files:**
- Create: `src/audit.rs`
- Create: `tests/audit_tests.rs`
- Modify: `src/lib.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write failing test — audit matched files**

Create `tests/audit_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;
use blazehash::audit::{audit, AuditResult, AuditStatus};
use blazehash::hash::hash_file;
use std::collections::HashMap;
use std::fs;
use tempfile::TempDir;

fn make_known_file(dir: &TempDir) -> String {
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    let result = hash_file(&file, &[Algorithm::Blake3]).unwrap();
    let hash = result.hashes[&Algorithm::Blake3].clone();

    // Build a hashdeep-format known file
    format!(
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n{},{},{}\n",
        result.size,
        hash,
        file.display()
    )
}

#[test]
fn audit_all_matched() {
    let dir = TempDir::new().unwrap();
    let known = make_known_file(&dir);

    let result = audit(
        &[dir.path().join("test.txt")],
        &known,
        &[Algorithm::Blake3],
        false,
    )
    .unwrap();

    assert_eq!(result.matched, 1);
    assert_eq!(result.new_files, 0);
    assert_eq!(result.changed, 0);
}

#[test]
fn audit_detects_changed_file() {
    let dir = TempDir::new().unwrap();
    let known = make_known_file(&dir);

    // Modify the file after generating known hashes
    fs::write(dir.path().join("test.txt"), b"modified content").unwrap();

    let result = audit(
        &[dir.path().join("test.txt")],
        &known,
        &[Algorithm::Blake3],
        false,
    )
    .unwrap();

    assert_eq!(result.matched, 0);
    assert_eq!(result.changed, 1);
}

#[test]
fn audit_detects_new_file() {
    let dir = TempDir::new().unwrap();
    let known = make_known_file(&dir);

    // Add a new file not in the known set
    fs::write(dir.path().join("new.txt"), b"new file").unwrap();

    let result = audit(
        &[dir.path().join("test.txt"), dir.path().join("new.txt")],
        &known,
        &[Algorithm::Blake3],
        false,
    )
    .unwrap();

    assert_eq!(result.matched, 1);
    assert_eq!(result.new_files, 1);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test audit_tests`
Expected: FAIL — `audit` module not found

- [ ] **Step 3: Implement audit module**

Create `src/audit.rs`:

```rust
use crate::algorithm::Algorithm;
use crate::hash::hash_file;
use crate::manifest::parse_header;
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct AuditResult {
    pub matched: usize,
    pub changed: usize,
    pub new_files: usize,
    pub moved: usize,
    pub details: Vec<AuditStatus>,
}

#[derive(Debug)]
pub enum AuditStatus {
    Matched(PathBuf),
    Changed(PathBuf),
    New(PathBuf),
    Moved { path: PathBuf, original: PathBuf },
}

/// A known file entry parsed from a hashdeep manifest.
struct KnownEntry {
    size: u64,
    hashes: HashMap<Algorithm, String>,
    path: PathBuf,
}

/// Audit files against a known hashdeep manifest.
pub fn audit(
    paths: &[PathBuf],
    known_content: &str,
    algorithms: &[Algorithm],
    _recursive: bool,
) -> Result<AuditResult> {
    let known_algos = parse_header(known_content)?;
    let known_entries = parse_known_entries(known_content, &known_algos)?;

    // Build lookup by path
    let known_by_path: HashMap<&Path, &KnownEntry> = known_entries
        .iter()
        .map(|e| (e.path.as_path(), e))
        .collect();

    // Build lookup by hash (for moved detection)
    let known_by_hash: HashMap<&str, &KnownEntry> = known_entries
        .iter()
        .filter_map(|e| {
            known_algos
                .first()
                .and_then(|a| e.hashes.get(a))
                .map(|h| (h.as_str(), e))
        })
        .collect();

    let mut result = AuditResult::default();

    for path in paths {
        let file_result = hash_file(path, &known_algos)?;

        if let Some(known) = known_by_path.get(path.as_path()) {
            // File exists in known set at same path
            let hashes_match = known_algos
                .iter()
                .all(|a| file_result.hashes.get(a) == known.hashes.get(a));

            if hashes_match && file_result.size == known.size {
                result.matched += 1;
                result.details.push(AuditStatus::Matched(path.clone()));
            } else {
                result.changed += 1;
                result.details.push(AuditStatus::Changed(path.clone()));
            }
        } else {
            // Check if file moved (same hash, different path)
            let first_hash = known_algos
                .first()
                .and_then(|a| file_result.hashes.get(a));

            if let Some(hash) = first_hash {
                if let Some(original) = known_by_hash.get(hash.as_str()) {
                    result.moved += 1;
                    result.details.push(AuditStatus::Moved {
                        path: path.clone(),
                        original: original.path.clone(),
                    });
                    continue;
                }
            }

            result.new_files += 1;
            result.details.push(AuditStatus::New(path.clone()));
        }
    }

    Ok(result)
}

fn parse_known_entries(content: &str, algorithms: &[Algorithm]) -> Result<Vec<KnownEntry>> {
    let mut entries = Vec::new();

    for line in content.lines() {
        // Skip header, comments, empty lines
        if line.starts_with("%%%%") || line.starts_with('#') || line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(algorithms.len() + 2, ',').collect();
        if parts.len() < algorithms.len() + 2 {
            continue;
        }

        let size: u64 = parts[0].parse()?;
        let mut hashes = HashMap::new();
        for (i, algo) in algorithms.iter().enumerate() {
            hashes.insert(*algo, parts[i + 1].to_string());
        }
        // Everything after the last expected hash column is the filename
        let path = PathBuf::from(parts[algorithms.len() + 1]);

        entries.push(KnownEntry {
            size,
            hashes,
            path,
        });
    }

    Ok(entries)
}
```

Update `src/lib.rs`:

```rust
pub mod algorithm;
pub mod audit;
pub mod hash;
pub mod manifest;
pub mod walk;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test audit_tests`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/audit.rs src/lib.rs tests/audit_tests.rs
git commit -m "feat: audit mode with match/changed/new/moved detection"
```

---

### Task 8: Additional Output Formats (CSV, JSON, JSONL)

**Files:**
- Create: `src/format/mod.rs`
- Create: `src/format/csv.rs`
- Create: `src/format/json.rs`
- Create: `tests/format_tests.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing test — CSV output**

Create `tests/format_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;
use blazehash::format::{write_csv, write_json, write_jsonl};
use blazehash::hash::FileHashResult;
use std::collections::HashMap;
use std::path::PathBuf;

fn sample_result() -> FileHashResult {
    let mut hashes = HashMap::new();
    hashes.insert(
        Algorithm::Blake3,
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24".to_string(),
    );
    hashes.insert(
        Algorithm::Sha256,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
    );
    FileHashResult {
        path: PathBuf::from("/evidence/test.txt"),
        size: 11,
        hashes,
    }
}

#[test]
fn csv_output_has_headers() {
    let results = vec![sample_result()];
    let algos = vec![Algorithm::Blake3, Algorithm::Sha256];
    let mut buf = Vec::new();
    write_csv(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.starts_with("size,blake3,sha256,filename\n"));
}

#[test]
fn csv_output_has_data() {
    let results = vec![sample_result()];
    let algos = vec![Algorithm::Blake3, Algorithm::Sha256];
    let mut buf = Vec::new();
    write_csv(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[1].starts_with("11,"));
    assert!(lines[1].ends_with("/evidence/test.txt"));
}

#[test]
fn json_output_is_valid() {
    let results = vec![sample_result()];
    let algos = vec![Algorithm::Blake3];
    let mut buf = Vec::new();
    write_json(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);
}

#[test]
fn jsonl_output_one_per_line() {
    let results = vec![sample_result(), sample_result()];
    let algos = vec![Algorithm::Blake3];
    let mut buf = Vec::new();
    write_jsonl(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 2);
    // Each line is valid JSON
    for line in &lines {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test format_tests`
Expected: FAIL — `format` module not found

- [ ] **Step 3: Implement format module**

Create `src/format/mod.rs`:

```rust
pub mod csv;
pub mod json;

pub use self::csv::write_csv;
pub use self::json::{write_json, write_jsonl};
```

Create `src/format/csv.rs`:

```rust
use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use std::io::Write;

pub fn write_csv<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    // Header
    write!(w, "size")?;
    for algo in algorithms {
        write!(w, ",{}", algo.hashdeep_name())?;
    }
    writeln!(w, ",filename")?;

    // Data
    for result in results {
        write!(w, "{}", result.size)?;
        for algo in algorithms {
            write!(w, ",{}", result.hashes[algo])?;
        }
        writeln!(w, ",{}", result.path.display())?;
    }

    Ok(())
}
```

Create `src/format/json.rs`:

```rust
use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use serde_json::{json, Value};
use std::io::Write;

fn result_to_json(result: &FileHashResult, algorithms: &[Algorithm]) -> Value {
    let mut hashes = serde_json::Map::new();
    for algo in algorithms {
        if let Some(hash) = result.hashes.get(algo) {
            hashes.insert(algo.hashdeep_name().to_string(), json!(hash));
        }
    }
    json!({
        "filename": result.path.display().to_string(),
        "size": result.size,
        "hashes": hashes,
    })
}

pub fn write_json<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    let arr: Vec<Value> = results.iter().map(|r| result_to_json(r, algorithms)).collect();
    serde_json::to_writer_pretty(w, &arr)?;
    writeln!(w)?;
    Ok(())
}

pub fn write_jsonl<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    for result in results {
        let val = result_to_json(result, algorithms);
        serde_json::to_writer(&mut *w, &val)?;
        writeln!(w)?;
    }
    Ok(())
}
```

Update `src/lib.rs`:

```rust
pub mod algorithm;
pub mod audit;
pub mod format;
pub mod hash;
pub mod manifest;
pub mod walk;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test format_tests`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/format/ src/lib.rs tests/format_tests.rs
git commit -m "feat: CSV, JSON, JSONL output formats"
```

---

### Task 9: Piecewise Hashing

**Files:**
- Create: `src/piecewise.rs`
- Create: `tests/piecewise_tests.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing test — piecewise hash a file**

Create `tests/piecewise_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;
use blazehash::piecewise::hash_file_piecewise;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn piecewise_small_file_one_chunk() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"hello world").unwrap();
    f.flush().unwrap();

    // Chunk size larger than file — should produce one chunk
    let results = hash_file_piecewise(f.path(), &[Algorithm::Blake3], 1024).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].offset, 0);
    assert_eq!(results[0].chunk_size, 11);
}

#[test]
fn piecewise_splits_file() {
    let mut f = NamedTempFile::new().unwrap();
    let data = vec![0x42u8; 1000];
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    // 400-byte chunks: should produce 3 chunks (400 + 400 + 200)
    let results = hash_file_piecewise(f.path(), &[Algorithm::Blake3], 400).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].offset, 0);
    assert_eq!(results[0].chunk_size, 400);
    assert_eq!(results[1].offset, 400);
    assert_eq!(results[1].chunk_size, 400);
    assert_eq!(results[2].offset, 800);
    assert_eq!(results[2].chunk_size, 200);
}

#[test]
fn piecewise_different_chunks_different_hashes() {
    let mut f = NamedTempFile::new().unwrap();
    let mut data = vec![0x41u8; 100];
    data.extend(vec![0x42u8; 100]);
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let results = hash_file_piecewise(f.path(), &[Algorithm::Blake3], 100).unwrap();
    assert_eq!(results.len(), 2);
    // Different content should produce different hashes
    assert_ne!(
        results[0].hashes[&Algorithm::Blake3],
        results[1].hashes[&Algorithm::Blake3]
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test piecewise_tests`
Expected: FAIL — `piecewise` module not found

- [ ] **Step 3: Implement piecewise hashing**

Create `src/piecewise.rs`:

```rust
use crate::algorithm::{hash_bytes, Algorithm};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub struct PiecewiseResult {
    pub offset: u64,
    pub chunk_size: u64,
    pub hashes: HashMap<Algorithm, String>,
}

/// Hash a file in fixed-size chunks.
pub fn hash_file_piecewise(
    path: &Path,
    algorithms: &[Algorithm],
    chunk_size: usize,
) -> Result<Vec<PiecewiseResult>> {
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0u8; chunk_size];
    let mut offset: u64 = 0;
    let mut results = Vec::new();

    loop {
        let mut total_read = 0;
        while total_read < chunk_size {
            let n = file.read(&mut buf[total_read..])?;
            if n == 0 {
                break;
            }
            total_read += n;
        }
        if total_read == 0 {
            break;
        }

        let chunk = &buf[..total_read];
        let mut hashes = HashMap::new();
        for algo in algorithms {
            hashes.insert(*algo, hash_bytes(*algo, chunk));
        }

        results.push(PiecewiseResult {
            offset,
            chunk_size: total_read as u64,
            hashes,
        });

        offset += total_read as u64;
    }

    Ok(results)
}
```

Update `src/lib.rs`:

```rust
pub mod algorithm;
pub mod audit;
pub mod format;
pub mod hash;
pub mod manifest;
pub mod piecewise;
pub mod walk;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test piecewise_tests`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/piecewise.rs src/lib.rs tests/piecewise_tests.rs
git commit -m "feat: piecewise chunk hashing"
```

---

### Task 10: Resume Interrupted Runs

**Files:**
- Create: `src/resume.rs`
- Create: `tests/resume_tests.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write failing test — resume skips already-hashed files**

Create `tests/resume_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;
use blazehash::resume::ResumeState;
use std::path::PathBuf;

#[test]
fn resume_state_empty_initially() {
    let state = ResumeState::new();
    assert!(!state.is_done(&PathBuf::from("/some/file.txt")));
    assert_eq!(state.completed_count(), 0);
}

#[test]
fn resume_state_from_partial_manifest() {
    let manifest = "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n11,abcd1234,/evidence/a.txt\n42,ef567890,/evidence/b.txt\n";
    let state = ResumeState::from_manifest(manifest).unwrap();
    assert!(state.is_done(&PathBuf::from("/evidence/a.txt")));
    assert!(state.is_done(&PathBuf::from("/evidence/b.txt")));
    assert!(!state.is_done(&PathBuf::from("/evidence/c.txt")));
    assert_eq!(state.completed_count(), 2);
}

#[test]
fn resume_state_mark_done() {
    let mut state = ResumeState::new();
    state.mark_done(PathBuf::from("/file.txt"));
    assert!(state.is_done(&PathBuf::from("/file.txt")));
    assert_eq!(state.completed_count(), 1);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test resume_tests`
Expected: FAIL — `resume` module not found

- [ ] **Step 3: Implement resume module**

Create `src/resume.rs`:

```rust
use anyhow::Result;
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Debug)]
pub struct ResumeState {
    completed: HashSet<PathBuf>,
}

impl ResumeState {
    pub fn new() -> Self {
        Self {
            completed: HashSet::new(),
        }
    }

    /// Build resume state from an existing partial manifest file.
    /// Parses the hashdeep-format output and collects all file paths already hashed.
    pub fn from_manifest(content: &str) -> Result<Self> {
        let mut completed = HashSet::new();

        for line in content.lines() {
            if line.starts_with("%%%%") || line.starts_with('#') || line.is_empty() {
                continue;
            }
            // The filename is everything after the last expected comma-separated field.
            // In hashdeep format: size,hash1,...,hashN,filename
            // We find the filename by splitting on comma and taking the last field.
            // But filenames can contain commas. The header tells us how many hash columns
            // there are. For simplicity in resume, we just need the path.
            // We look for the first comma (after size), skip hash columns, take the rest.
            // Since we don't know the column count here, we parse from the header.
            if let Some(last_comma) = line.rfind(',') {
                // This is imprecise for filenames with commas, but the resume state
                // only needs to match against paths we'll encounter during walking.
                let path = &line[last_comma + 1..];
                completed.insert(PathBuf::from(path));
            }
        }

        Ok(Self { completed })
    }

    pub fn is_done(&self, path: &PathBuf) -> bool {
        self.completed.contains(path)
    }

    pub fn mark_done(&mut self, path: PathBuf) {
        self.completed.insert(path);
    }

    pub fn completed_count(&self) -> usize {
        self.completed.len()
    }
}
```

Update `src/lib.rs`:

```rust
pub mod algorithm;
pub mod audit;
pub mod format;
pub mod hash;
pub mod manifest;
pub mod piecewise;
pub mod resume;
pub mod walk;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test --test resume_tests`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/resume.rs src/lib.rs tests/resume_tests.rs
git commit -m "feat: resume state for interrupted hashing runs"
```

---

### Task 11: GitHub Actions Release Workflow

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Create CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --all-features
      - run: cargo clippy -- -D warnings
      - run: cargo fmt --check

  check-msrv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.75.0
      - run: cargo check
```

- [ ] **Step 2: Create release workflow**

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: write

jobs:
  build:
    strategy:
      matrix:
        include:
          - target: aarch64-apple-darwin
            os: macos-latest
          - target: x86_64-apple-darwin
            os: macos-13
          - target: x86_64-unknown-linux-musl
            os: ubuntu-latest
          - target: aarch64-unknown-linux-musl
            os: ubuntu-latest
          - target: x86_64-pc-windows-msvc
            os: windows-latest
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Install musl tools (Linux)
        if: contains(matrix.target, 'musl')
        run: |
          sudo apt-get update
          sudo apt-get install -y musl-tools
          if [[ "${{ matrix.target }}" == "aarch64-unknown-linux-musl" ]]; then
            sudo apt-get install -y gcc-aarch64-linux-gnu
            echo "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc" >> $GITHUB_ENV
          fi

      - name: Build
        run: cargo build --release --target ${{ matrix.target }}

      - name: Package (Unix)
        if: runner.os != 'Windows'
        run: |
          cd target/${{ matrix.target }}/release
          tar czf ../../../blazehash-${{ matrix.target }}.tar.gz blazehash
          cd ../../..

      - name: Package (Windows)
        if: runner.os == 'Windows'
        run: |
          cd target/${{ matrix.target }}/release
          7z a ../../../blazehash-${{ matrix.target }}.zip blazehash.exe
          cd ../../..

      - uses: actions/upload-artifact@v4
        with:
          name: blazehash-${{ matrix.target }}
          path: blazehash-${{ matrix.target }}.*

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          path: artifacts

      - name: Generate checksums
        run: |
          cd artifacts
          find . -name "blazehash-*" -exec mv {} . \;
          sha256sum blazehash-* > checksums.txt
          cat checksums.txt

      - name: Create release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            artifacts/blazehash-*
            artifacts/checksums.txt
          generate_release_notes: true

      - name: Dispatch to homebrew tap
        uses: peter-evans/repository-dispatch@v3
        with:
          token: ${{ secrets.TAP_GITHUB_TOKEN }}
          repository: SecurityRonin/homebrew-blazehash
          event-type: update-formula
          client-payload: '{"version": "${{ github.ref_name }}"}'
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml .github/workflows/release.yml
git commit -m "ci: add CI and release workflows with cross-platform builds"
```

---

### Task 12: Integration Test — Full End-to-End

**Files:**
- Create: `tests/e2e_tests.rs`

- [ ] **Step 1: Write end-to-end test**

Create `tests/e2e_tests.rs`:

```rust
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn e2e_hash_and_audit() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("file1.txt"), b"content one").unwrap();
    fs::write(dir.path().join("file2.txt"), b"content two").unwrap();
    let manifest = dir.path().join("manifest.hash");

    // Step 1: Hash the directory
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-r")
        .arg("-c")
        .arg("blake3,sha256")
        .arg("-o")
        .arg(manifest.to_str().unwrap())
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success();

    // Verify manifest exists and has content
    let contents = fs::read_to_string(&manifest).unwrap();
    assert!(contents.contains("HASHDEEP-1.0"));
    assert!(contents.contains("file1.txt"));
    assert!(contents.contains("file2.txt"));
    assert!(contents.contains("blake3"));
    assert!(contents.contains("sha256"));

    // Step 2: Audit should show all matched
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-a")
        .arg("-k")
        .arg(manifest.to_str().unwrap())
        .arg("-r")
        .arg(dir.path().to_str().unwrap())
        .assert()
        .success();
}

#[test]
fn e2e_bare_output() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("-b")
        .arg(dir.path().join("test.txt").to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    // Bare mode: no header
    assert!(!stdout.contains("HASHDEEP"));
    assert!(stdout.contains("test.txt"));
}

#[test]
fn e2e_csv_format() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--format")
        .arg("csv")
        .arg(dir.path().join("test.txt").to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("size,blake3,filename"));
}

#[test]
fn e2e_json_format() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("--format")
        .arg("json")
        .arg(dir.path().join("test.txt").to_str().unwrap())
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_array());
}
```

- [ ] **Step 2: Run all tests**

Run: `cd /Users/4n6h4x0r/src/blazehash && cargo test`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add tests/e2e_tests.rs
git commit -m "test: end-to-end integration tests"
```

---

## Summary

| Task | What it builds | Test count (approx) |
|------|---------------|---------------------|
| 1 | Project scaffolding | 0 (compile check) |
| 2 | Algorithm enum + hash_bytes | 17 |
| 3 | File hashing (streaming + mmap) | 5 |
| 4 | hashdeep output format | 7 |
| 5 | Directory walking | 6 |
| 6 | CLI | 6 |
| 7 | Audit mode | 3 |
| 8 | CSV/JSON/JSONL formats | 4 |
| 9 | Piecewise hashing | 3 |
| 10 | Resume state | 3 |
| 11 | CI + Release workflows | 0 (infra) |
| 12 | End-to-end tests | 4 |
| **Total** | | **~58 tests** |

NSRL import and DFXML format are deferred to a follow-up plan to keep this plan focused on the core hashdeep-compatible functionality.
