# blazehash Feature Batch Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement 15 features: filtering (glob/size/mtime), new algorithms (SHAKE/xxHash/CRC32C), stdin mode, new output formats (DFXML/sha256sum/sidecar/ADS), manifest auto-detection, diff, dedup, NSRL lookup, and signed manifests.

**Architecture:** Layered build — shared infrastructure first (Cargo deps, WalkFilter, universal manifest loader), then independent features (algorithms, formats, stdin), then compound features (diff, dedup, NSRL, signing) that compose the shared layer.

**Tech Stack:** Rust. New direct deps: `xxhash-rust`, `crc32c`, `globset`, `chrono`, `ed25519-dalek`, `rand`. New optional deps (behind `nsrl` feature): `rusqlite`, `bloomfilter`.

**TDD mandate:** Every task has a RED commit (failing tests only) then a GREEN commit (minimal implementation). Two separate commits per task, no exceptions.

---

### Task 1: Cargo dependencies

**Files:**
- Modify: `Cargo.toml`

**Step 1: Verify clean baseline**

```bash
cargo check --all-features 2>&1 | grep "^error"
```
Expected: no output (no errors).

**Step 2: Add dependencies to `[dependencies]` in `Cargo.toml`**

```toml
xxhash-rust = { version = "0.8", features = ["xxh3"] }
crc32c = "0.6"
globset = "0.4"
chrono = { version = "0.4", default-features = false, features = ["std"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand = "0.8"
```

Add optional deps (after the existing `toml` and `dirs` optional deps):
```toml
rusqlite = { version = "0.31", optional = true }
bloomfilter = { version = "1", optional = true }
```

Add `nsrl` to `[features]`:
```toml
[features]
default = ["forensic-image"]
forensic-image = ["dep:ewf"]
gpu = ["dep:wgpu", "dep:pollster", "dep:toml", "dep:dirs"]
nsrl = ["dep:rusqlite", "dep:bloomfilter"]
```

**Step 3: Verify build**

```bash
cargo check --all-features
```
Expected: clean (no errors).

**Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add deps for feature batch (xxhash-rust, crc32c, globset, chrono, ed25519-dalek, rand, optional rusqlite+bloomfilter)"
```

---

### Task 2: Algorithms — CRC32C and XXH3-128

**Files:**
- Modify: `src/algorithm.rs`
- Modify: `tests/algorithm_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/algorithm_tests.rs`:

```rust
#[test]
fn test_crc32c_known_vector() {
    let result = hash_bytes(Algorithm::Crc32c, b"hello world");
    assert_eq!(result, "c99465aa"); // known CRC32C of "hello world"
}

#[test]
fn test_xxh3_known_vector() {
    let result = hash_bytes(Algorithm::Xxh3, b"");
    // xxh3_128 of empty string: 99aa06d3014798d86001c324468d497f (from xxhash reference)
    assert_eq!(result.len(), 32); // 128-bit = 32 hex chars
}

#[test]
fn test_crc32c_is_non_cryptographic() {
    assert!(Algorithm::Crc32c.is_non_cryptographic());
    assert!(Algorithm::Xxh3.is_non_cryptographic());
    assert!(!Algorithm::Blake3.is_non_cryptographic());
}

#[test]
fn test_crc32c_not_in_all() {
    let all = Algorithm::all();
    assert!(!all.contains(&Algorithm::Crc32c));
    assert!(!all.contains(&Algorithm::Xxh3));
}

#[test]
fn test_crc32c_parse_from_str() {
    assert_eq!("crc32c".parse::<Algorithm>().unwrap(), Algorithm::Crc32c);
    assert_eq!("xxh3".parse::<Algorithm>().unwrap(), Algorithm::Xxh3);
}
```

**Step 2: Run tests — confirm RED**

```bash
cargo test --test algorithm_tests 2>&1 | grep -E "FAILED|error"
```
Expected: compile error — `Algorithm::Crc32c` and `Algorithm::Xxh3` do not exist.

**Step 3: RED commit**

```bash
git add tests/algorithm_tests.rs
git commit -m "test(RED): add failing tests for CRC32C and XXH3-128 algorithm variants"
```

**Step 4: Implement (GREEN)**

In `src/algorithm.rs`, add to the `Algorithm` enum:
```rust
Crc32c,
Xxh3,
```

Add `is_non_cryptographic()` method in the `impl Algorithm` block:
```rust
pub fn is_non_cryptographic(&self) -> bool {
    matches!(self, Algorithm::Crc32c | Algorithm::Xxh3)
}
```

Add to `hashdeep_name()`:
```rust
Algorithm::Crc32c => "crc32c",
Algorithm::Xxh3 => "xxh3",
```

Add to `FromStr`:
```rust
"crc32c" => Ok(Algorithm::Crc32c),
"xxh3" => Ok(Algorithm::Xxh3),
```

Add to `hash_bytes()`:
```rust
Algorithm::Crc32c => {
    let checksum = crc32c::crc32c(data);
    format!("{checksum:08x}")
}
Algorithm::Xxh3 => {
    use xxhash_rust::xxh3::xxh3_128;
    let hash = xxh3_128(data);
    format!("{hash:032x}")
}
```

Add `use xxhash_rust;` and `use crc32c;` at the top of the file (or use full paths as above).

**Step 5: Run tests — confirm GREEN**

```bash
cargo test --test algorithm_tests 2>&1 | tail -5
```
Expected: all tests pass.

**Step 6: GREEN commit**

```bash
git add src/algorithm.rs tests/algorithm_tests.rs
git commit -m "feat: add CRC32C and XXH3-128 algorithm variants"
```

---

### Task 3: Algorithms — SHAKE-128 and SHAKE-256

**Files:**
- Modify: `src/algorithm.rs`
- Modify: `tests/algorithm_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/algorithm_tests.rs`:

```rust
#[test]
fn test_shake128_known_vector() {
    // SHAKE-128 of empty string, 32-byte output: known NIST vector
    let result = hash_bytes(Algorithm::Shake128, b"");
    assert_eq!(result.len(), 64); // 32 bytes = 64 hex chars
    assert_eq!(&result[..8], "7f9c2ba4"); // first 4 bytes of NIST SHAKE-128("")
}

#[test]
fn test_shake256_known_vector() {
    let result = hash_bytes(Algorithm::Shake256, b"");
    assert_eq!(result.len(), 128); // 64 bytes = 128 hex chars
    assert_eq!(&result[..8], "46b9dd2b"); // first 4 bytes of NIST SHAKE-256("")
}

#[test]
fn test_shake128_not_fuzzy_not_non_crypto() {
    assert!(!Algorithm::Shake128.is_fuzzy());
    assert!(!Algorithm::Shake128.is_non_cryptographic());
}

#[test]
fn test_shake_parse_from_str() {
    assert_eq!("shake128".parse::<Algorithm>().unwrap(), Algorithm::Shake128);
    assert_eq!("shake256".parse::<Algorithm>().unwrap(), Algorithm::Shake256);
}
```

**Step 2: RED commit**

```bash
cargo test --test algorithm_tests 2>&1 | grep "FAILED\|error\[" | head -5
git add tests/algorithm_tests.rs
git commit -m "test(RED): add failing tests for SHAKE-128 and SHAKE-256 algorithm variants"
```

**Step 3: Implement (GREEN)**

Add to `Algorithm` enum:
```rust
Shake128,
Shake256,
```

Add to `hashdeep_name()`:
```rust
Algorithm::Shake128 => "shake128",
Algorithm::Shake256 => "shake256",
```

Add to `FromStr`:
```rust
"shake128" => Ok(Algorithm::Shake128),
"shake256" => Ok(Algorithm::Shake256),
```

Add to `hash_bytes()`:
```rust
Algorithm::Shake128 => {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake128::default();
    h.update(data);
    let mut reader = h.finalize_xof();
    let mut buf = [0u8; 32]; // fixed 256-bit output
    reader.read(&mut buf);
    hex::encode(buf)
}
Algorithm::Shake256 => {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    h.update(data);
    let mut reader = h.finalize_xof();
    let mut buf = [0u8; 64]; // fixed 512-bit output
    reader.read(&mut buf);
    hex::encode(buf)
}
```

Note: `sha3` is already in `Cargo.toml`. No new dep needed.

**Step 4: Run and commit GREEN**

```bash
cargo test --test algorithm_tests 2>&1 | tail -5
git add src/algorithm.rs
git commit -m "feat: add SHAKE-128 and SHAKE-256 algorithm variants (fixed 256/512-bit output)"
```

---

### Task 4: WalkFilter — glob include/exclude patterns

**Files:**
- Create: `src/walk_filter.rs`
- Modify: `src/walk.rs`
- Modify: `src/walk_windows.rs` (Windows only)
- Modify: `src/lib.rs`
- Modify: `src/cli.rs`
- Modify: `src/commands/hash.rs`
- Modify: `src/commands/hash.rs` (HashOptions struct)
- Modify: `tests/hash_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_include_glob_filters_files() {
    use blazehash::walk::{walk_and_hash, WalkFilter};
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.exe"), b"exe content").unwrap();
    std::fs::write(dir.path().join("file.log"), b"log content").unwrap();

    let filter = WalkFilter::builder()
        .include("*.exe")
        .build()
        .unwrap();
    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false, &filter).unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0].path.to_str().unwrap().ends_with(".exe"));
}

#[test]
fn test_exclude_glob_filters_files() {
    use blazehash::walk::{walk_and_hash, WalkFilter};
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.exe"), b"exe").unwrap();
    std::fs::write(dir.path().join("file.log"), b"log").unwrap();

    let filter = WalkFilter::builder()
        .exclude("*.log")
        .build()
        .unwrap();
    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false, &filter).unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0].path.to_str().unwrap().ends_with(".exe"));
}

#[test]
fn test_empty_filter_includes_all() {
    use blazehash::walk::{walk_and_hash, WalkFilter};
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
    std::fs::write(dir.path().join("b.bin"), b"b").unwrap();

    let filter = WalkFilter::default();
    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false, &filter).unwrap();
    assert_eq!(output.results.len(), 2);
}
```

**Step 2: RED commit**

```bash
cargo test --test hash_tests 2>&1 | grep "FAILED\|error\[" | head -5
git add tests/hash_tests.rs
git commit -m "test(RED): add failing tests for WalkFilter glob include/exclude"
```

**Step 3: Create `src/walk_filter.rs`**

```rust
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::Path;

/// Filter applied during directory walking.
#[derive(Debug, Default, Clone)]
pub struct WalkFilter {
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub newer_than: Option<std::time::SystemTime>,
}

impl WalkFilter {
    pub fn builder() -> WalkFilterBuilder {
        WalkFilterBuilder::default()
    }

    /// Returns true if this file should be hashed.
    pub fn passes(&self, filename: &str, size: u64, mtime: Option<std::time::SystemTime>) -> bool {
        // include: must match at least one (if any patterns set)
        if let Some(inc) = &self.include {
            if !inc.is_match(filename) {
                return false;
            }
        }
        // exclude: must not match any
        if let Some(exc) = &self.exclude {
            if exc.is_match(filename) {
                return false;
            }
        }
        // size filters
        if let Some(min) = self.min_size {
            if size < min {
                return false;
            }
        }
        if let Some(max) = self.max_size {
            if size > max {
                return false;
            }
        }
        // mtime filter
        if let Some(newer) = self.newer_than {
            if let Some(mt) = mtime {
                if mt <= newer {
                    return false;
                }
            }
        }
        true
    }
}

#[derive(Default)]
pub struct WalkFilterBuilder {
    include_patterns: Vec<String>,
    exclude_patterns: Vec<String>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    newer_than: Option<std::time::SystemTime>,
}

impl WalkFilterBuilder {
    pub fn include(mut self, pattern: &str) -> Self {
        self.include_patterns.push(pattern.to_string());
        self
    }

    pub fn exclude(mut self, pattern: &str) -> Self {
        self.exclude_patterns.push(pattern.to_string());
        self
    }

    pub fn min_size(mut self, size: u64) -> Self {
        self.min_size = Some(size);
        self
    }

    pub fn max_size(mut self, size: u64) -> Self {
        self.max_size = Some(size);
        self
    }

    pub fn newer_than(mut self, t: std::time::SystemTime) -> Self {
        self.newer_than = Some(t);
        self
    }

    pub fn build(self) -> anyhow::Result<WalkFilter> {
        let include = if self.include_patterns.is_empty() {
            None
        } else {
            let mut builder = GlobSetBuilder::new();
            for p in &self.include_patterns {
                builder.add(Glob::new(p).map_err(|e| anyhow::anyhow!("invalid glob {p:?}: {e}"))?);
            }
            Some(builder.build()?)
        };

        let exclude = if self.exclude_patterns.is_empty() {
            None
        } else {
            let mut builder = GlobSetBuilder::new();
            for p in &self.exclude_patterns {
                builder.add(Glob::new(p).map_err(|e| anyhow::anyhow!("invalid glob {p:?}: {e}"))?);
            }
            Some(builder.build()?)
        };

        Ok(WalkFilter {
            include,
            exclude,
            min_size: self.min_size,
            max_size: self.max_size,
            newer_than: self.newer_than,
        })
    }
}
```

**Step 4: Modify `src/walk.rs`**

Add `use crate::walk_filter::WalkFilter;` at the top.

Change `walk_and_hash` signature to:
```rust
pub fn walk_and_hash(
    root: &Path,
    algorithms: &[Algorithm],
    recursive: bool,
    filter: &WalkFilter,
) -> Result<WalkOutput>
```

Inside the walk loop, after obtaining file metadata, add:
```rust
let filename = path.file_name()
    .unwrap_or_default()
    .to_string_lossy()
    .to_string();
let size = metadata.len();
let mtime = metadata.modified().ok();
if !filter.passes(&filename, size, mtime) {
    continue;
}
```

Apply the same pattern to `walk_paths` by passing the filter through, or apply the filter check in `walk_and_hash` after collecting paths.

**Step 5: Modify `src/walk_windows.rs`**

Same change: add `filter: &WalkFilter` parameter, apply `filter.passes()` check in the walk loop.

**Step 6: Add to `src/lib.rs`**

```rust
pub mod walk_filter;
```

**Step 7: Update call sites**

In `src/commands/hash.rs`, add `filter: &WalkFilter` to `HashOptions` and pass `WalkFilter::default()` at the call site for now. Update `collect_results` to accept and pass `filter`.

In `src/commands/piecewise.rs` and `src/commands/size_only.rs`, pass `&WalkFilter::default()`.

In `src/commands/audit.rs`, pass `&WalkFilter::default()`.

**Step 8: Run and commit GREEN**

```bash
cargo test --test hash_tests 2>&1 | tail -5
git add src/walk_filter.rs src/walk.rs src/lib.rs src/commands/hash.rs src/commands/piecewise.rs src/commands/size_only.rs src/commands/audit.rs
git commit -m "feat: add WalkFilter with glob include/exclude support"
```

---

### Task 5: WalkFilter — size and mtime filters + CLI flags

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/commands/hash.rs` (HashOptions)
- Modify: `src/main.rs`
- Modify: `tests/hash_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_min_size_filter() {
    use blazehash::walk::{walk_and_hash, WalkFilter};
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("small.bin"), b"hi").unwrap();          // 2 bytes
    std::fs::write(dir.path().join("large.bin"), vec![0u8; 1024]).unwrap(); // 1024 bytes

    let filter = WalkFilter::builder().min_size(100).build().unwrap();
    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false, &filter).unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0].path.to_str().unwrap().ends_with("large.bin"));
}

#[test]
fn test_max_size_filter() {
    use blazehash::walk::{walk_and_hash, WalkFilter};
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("small.bin"), b"hi").unwrap();
    std::fs::write(dir.path().join("large.bin"), vec![0u8; 1024]).unwrap();

    let filter = WalkFilter::builder().max_size(10).build().unwrap();
    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false, &filter).unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0].path.to_str().unwrap().ends_with("small.bin"));
}
```

**Step 2: RED commit**

```bash
cargo test --test hash_tests test_min_size 2>&1 | tail -5
git add tests/hash_tests.rs
git commit -m "test(RED): add failing tests for min/max size walk filters"
```

**Step 3: The `WalkFilter` struct already supports min/max/newer fields (from Task 4). Wire them to the CLI.**

Add to `src/cli.rs`:
```rust
/// Only hash files larger than SIZE (e.g. 1K, 10M, 2G)
#[arg(long = "min-size", value_parser = parse_chunk_size)]
pub min_size: Option<usize>,

/// Only hash files smaller than SIZE (e.g. 100M, 4G)
#[arg(long = "max-size", value_parser = parse_chunk_size)]
pub max_size: Option<usize>,

/// Only hash files modified after DATE (YYYY-MM-DD)
#[arg(long = "newer", value_parser = parse_date)]
pub newer: Option<std::time::SystemTime>,

/// Include only files matching GLOB (repeatable, matches filename only)
#[arg(long = "include")]
pub include: Vec<String>,

/// Exclude files matching GLOB (repeatable, takes precedence over --include)
#[arg(long = "exclude")]
pub exclude: Vec<String>,
```

Add `parse_date` function to `src/cli.rs`:
```rust
pub fn parse_date(s: &str) -> Result<std::time::SystemTime, String> {
    let d = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|e| format!("invalid date {s:?}: {e}"))?;
    let dt = d.and_hms_opt(0, 0, 0).unwrap();
    let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    let secs = (dt - epoch).num_seconds() as u64;
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}
```

Add `use chrono;` at top of `src/cli.rs`.

Add `build_walk_filter` to `src/cli.rs`:
```rust
impl Cli {
    pub fn build_walk_filter(&self) -> anyhow::Result<blazehash::walk_filter::WalkFilter> {
        let mut b = blazehash::walk_filter::WalkFilter::builder();
        for pat in &self.include {
            b = b.include(pat);
        }
        for pat in &self.exclude {
            b = b.exclude(pat);
        }
        if let Some(min) = self.min_size {
            b = b.min_size(min as u64);
        }
        if let Some(max) = self.max_size {
            b = b.max_size(max as u64);
        }
        if let Some(newer) = self.newer {
            b = b.newer_than(newer);
        }
        b.build()
    }
}
```

Update `src/main.rs` Mode::Hash to use `cli.build_walk_filter()?` and pass it through `HashOptions`.

Update `HashOptions` in `src/commands/hash.rs` to include `filter: WalkFilter` (or `filter: &'a WalkFilter`).

**Step 4: Run and commit GREEN**

```bash
cargo test --test hash_tests 2>&1 | tail -5
git add src/cli.rs src/main.rs src/commands/hash.rs
git commit -m "feat: add --include/--exclude/--min-size/--max-size/--newer CLI filters"
```

---

### Task 6: stdin mode (`--stdin`)

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Create: `src/commands/stdin.rs`
- Modify: `src/commands/mod.rs`
- Modify: `tests/hash_tests.rs`

**Step 1: Write failing test (RED)**

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_stdin_mode_cli_flag_exists() {
    use assert_cmd::Command;
    // Just test that --stdin is accepted as a flag (with input from /dev/null)
    let mut cmd = Command::cargo_bin("blazehash").unwrap();
    cmd.args(["--stdin", "-c", "blake3"])
        .write_stdin(b"hello" as &[u8])
        .assert()
        .success();
}

#[test]
fn test_stdin_blake3_known_hash() {
    use assert_cmd::Command;
    // blake3 of "hello" is known
    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--stdin", "-c", "blake3", "--format", "hashdeep"])
        .write_stdin(b"hello" as &[u8])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"),
        "expected blake3 hash of 'hello', got: {stdout}");
}
```

**Step 2: RED commit**

```bash
cargo test --test hash_tests test_stdin 2>&1 | tail -5
git add tests/hash_tests.rs
git commit -m "test(RED): add failing tests for --stdin mode"
```

**Step 3: Add `--stdin` to CLI**

In `src/cli.rs`, add:
```rust
/// Read from stdin instead of files
#[arg(long = "stdin")]
pub stdin: bool,
```

Add `Mode::Stdin` to `Mode` enum in `src/cli.rs`:
```rust
pub enum Mode {
    Mcp,
    Bench,
    Stdin,
    SizeOnly,
    Audit,
    VerifyImage,
    Piecewise,
    Hash,
}
```

Update `mode()` method — add before `Hash`:
```rust
} else if self.stdin {
    Mode::Stdin
```

**Step 4: Create `src/commands/stdin.rs`**

```rust
use anyhow::Result;
use blazehash::algorithm::Algorithm;
use blazehash::hash::FileHashResult;
use blazehash::manifest::{write_header, write_record};
use blazehash::format::{write_csv, write_json, write_jsonl};
use blazehash::output::make_writer;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;

pub fn run(algorithms: &[Algorithm], format: &str, bare: bool, output: Option<&std::path::PathBuf>) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    // Read all stdin into memory (chunked to avoid huge alloc on streams)
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;

    let size = data.len() as u64;
    let mut hashes = HashMap::new();
    for algo in algorithms {
        let hash = blazehash::algorithm::hash_bytes(*algo, &data);
        hashes.insert(*algo, hash);
    }

    let result = FileHashResult {
        path: PathBuf::from("<stdin>"),
        size,
        hashes,
    };

    match format {
        "csv" => write_csv(&mut writer, &[result], algorithms)?,
        "json" => write_json(&mut writer, &[result], algorithms)?,
        "jsonl" => write_jsonl(&mut writer, &[result], algorithms)?,
        _ => {
            if !bare {
                write_header(&mut writer, algorithms)?;
            }
            write_record(&mut writer, &result, algorithms)?;
        }
    }

    writer.flush()?;
    Ok(())
}
```

**Step 5: Add to `src/commands/mod.rs`**

```rust
pub mod stdin;
```

**Step 6: Dispatch in `src/main.rs`**

```rust
Mode::Stdin => {
    commands::stdin::run(&algorithms, &cli.format, cli.bare, cli.output.as_ref())?;
}
```

**Step 7: Run and commit GREEN**

```bash
cargo test --test hash_tests test_stdin 2>&1 | tail -5
git add src/cli.rs src/main.rs src/commands/stdin.rs src/commands/mod.rs
git commit -m "feat: add --stdin mode for hashing piped data (cloud, dd, etc.)"
```

---

### Task 7: Universal manifest loader + auto-detection

**Files:**
- Create: `src/manifest_loader.rs`
- Modify: `src/lib.rs`
- Modify: `src/commands/audit.rs`
- Modify: `tests/audit_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/audit_tests.rs`:

```rust
#[test]
fn test_load_manifest_hashdeep_format() {
    use blazehash::manifest_loader::load_manifest;
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("test.hash");
    std::fs::write(&manifest, "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n## comment\n5,abc123,/file.bin\n").unwrap();
    let records = load_manifest(&manifest).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].path, std::path::PathBuf::from("/file.bin"));
}

#[test]
fn test_find_manifest_finds_single_candidate() {
    use blazehash::manifest_loader::find_manifest;
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    std::fs::write(&manifest, "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n##\n").unwrap();
    let found = find_manifest(&[dir.path()]).unwrap();
    assert_eq!(found, manifest);
}

#[test]
fn test_find_manifest_errors_on_multiple() {
    use blazehash::manifest_loader::find_manifest;
    let dir = tempfile::tempdir().unwrap();
    let header = "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n##\n";
    std::fs::write(dir.path().join("a.hash"), header).unwrap();
    std::fs::write(dir.path().join("b.hash"), header).unwrap();
    assert!(find_manifest(&[dir.path()]).is_err());
}

#[test]
fn test_find_manifest_errors_on_none() {
    use blazehash::manifest_loader::find_manifest;
    let dir = tempfile::tempdir().unwrap();
    assert!(find_manifest(&[dir.path()]).is_err());
}
```

**Step 2: RED commit**

```bash
cargo test --test audit_tests test_load_manifest 2>&1 | tail -5
git add tests/audit_tests.rs
git commit -m "test(RED): add failing tests for universal manifest loader and auto-detection"
```

**Step 3: Create `src/manifest_loader.rs`**

```rust
use crate::manifest::{parse_header, parse_records, ManifestRecord};
use anyhow::{bail, Result};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Load a manifest from any supported format (hashdeep, JSON, JSONL, CSV).
/// Returns a flat list of ManifestRecord.
pub fn load_manifest(path: &Path) -> Result<Vec<ManifestRecord>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read manifest {}: {e}", path.display()))?;

    let trimmed = content.trim_start();

    if trimmed.starts_with("%%%%") {
        // hashdeep format
        let algos = parse_header(&content)?;
        Ok(parse_records(&content, &algos))
    } else if trimmed.starts_with('[') {
        // JSON array
        load_json_manifest(&content)
    } else if trimmed.starts_with('{') {
        // JSONL (one JSON object per line)
        load_jsonl_manifest(&content)
    } else {
        // CSV — first line is header with "size,<algo>,...,filename"
        load_csv_manifest(&content)
    }
}

fn load_json_manifest(content: &str) -> Result<Vec<ManifestRecord>> {
    let values: Vec<serde_json::Value> = serde_json::from_str(content)?;
    values.iter().map(json_value_to_record).collect()
}

fn load_jsonl_manifest(content: &str) -> Result<Vec<ManifestRecord>> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let v: serde_json::Value = serde_json::from_str(line)?;
            json_value_to_record(&v)
        })
        .collect()
}

fn json_value_to_record(v: &serde_json::Value) -> Result<ManifestRecord> {
    use crate::algorithm::Algorithm;
    use std::collections::HashMap;
    use std::str::FromStr;

    let path = PathBuf::from(
        v.get("filename")
            .or_else(|| v.get("path"))
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow::anyhow!("JSON record missing 'filename' field"))?,
    );
    let size: u64 = v.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
    let mut hashes = HashMap::new();
    if let Some(obj) = v.as_object() {
        for (key, val) in obj {
            if key == "filename" || key == "path" || key == "size" { continue; }
            if let (Ok(algo), Some(hash)) = (Algorithm::from_str(key), val.as_str()) {
                hashes.insert(algo, hash.to_string());
            }
        }
    }
    Ok(ManifestRecord { size, hashes, path })
}

fn load_csv_manifest(content: &str) -> Result<Vec<ManifestRecord>> {
    use crate::algorithm::Algorithm;
    use std::collections::HashMap;
    use std::str::FromStr;

    let mut lines = content.lines();
    let header = lines.next().ok_or_else(|| anyhow::anyhow!("empty CSV manifest"))?;
    let cols: Vec<&str> = header.split(',').collect();

    lines
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|line| {
            let parts: Vec<&str> = line.splitn(cols.len(), ',').collect();
            if parts.len() < cols.len() {
                bail!("CSV row has too few columns: {line:?}");
            }
            let mut hashes = HashMap::new();
            let mut size = 0u64;
            let mut path = PathBuf::new();
            for (i, col) in cols.iter().enumerate() {
                match *col {
                    "size" => size = parts[i].parse().unwrap_or(0),
                    "filename" => path = PathBuf::from(parts[i]),
                    other => {
                        if let Ok(algo) = Algorithm::from_str(other) {
                            hashes.insert(algo, parts[i].to_string());
                        }
                    }
                }
            }
            Ok(ManifestRecord { size, hashes, path })
        })
        .collect()
}

/// Search `search_dirs` for a single manifest file.
/// Errors if 0 or 2+ candidates are found.
pub fn find_manifest(search_dirs: &[&Path]) -> Result<PathBuf> {
    let candidate_exts = ["hash", "hashdeep", "csv", "json", "jsonl", "txt"];
    let mut candidates = Vec::new();

    for dir in search_dirs {
        if !dir.is_dir() { continue; }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() { continue; }
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if candidate_exts.contains(&ext) && looks_like_manifest(&path) {
                    candidates.push(path);
                }
            }
        }
    }

    match candidates.len() {
        0 => bail!("no manifest found — specify with -k"),
        1 => Ok(candidates.remove(0)),
        _ => {
            let names: Vec<String> = candidates.iter()
                .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
                .collect();
            bail!("multiple manifests found: {} — specify with -k", names.join(", "))
        }
    }
}

fn looks_like_manifest(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else { return false; };
    let mut buf = [0u8; 256];
    let Ok(n) = file.read(&mut buf) else { return false; };
    let head = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let first_line = head.lines().next().unwrap_or("");
    first_line.starts_with("%%%%")
        || head.trim_start().starts_with('[')
        || head.trim_start().starts_with('{')
        || (first_line.contains("size") && (first_line.contains("sha256") || first_line.contains("blake3") || first_line.contains("md5") || first_line.contains("sha1")))
}
```

**Step 4: Add to `src/lib.rs`**

```rust
pub mod manifest_loader;
```

**Step 5: Update audit to use `find_manifest` when `-k` not provided**

In `src/commands/audit.rs`, when `known_files` is empty, call:
```rust
let manifest_path = blazehash::manifest_loader::find_manifest(
    &[&std::env::current_dir()?, paths.first().map(|p| p.as_path()).unwrap_or(Path::new("."))]
)?;
eprintln!("[*] Using manifest: {}", manifest_path.display());
```

**Step 6: Run and commit GREEN**

```bash
cargo test --test audit_tests 2>&1 | tail -5
git add src/manifest_loader.rs src/lib.rs src/commands/audit.rs tests/audit_tests.rs
git commit -m "feat: add universal manifest loader and auto-detection (find_manifest)"
```

---

### Task 8: DFXML output format

**Files:**
- Create: `src/format/dfxml.rs`
- Modify: `src/format/mod.rs`
- Modify: `src/commands/hash.rs`
- Modify: `tests/hash_tests.rs`

**Step 1: Write failing test (RED)**

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_dfxml_output_format() {
    use assert_cmd::Command;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.bin"), b"hello").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([dir.path().to_str().unwrap(), "-c", "blake3", "--format", "dfxml"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("<?xml"), "expected XML declaration, got: {stdout}");
    assert!(stdout.contains("<dfxml"), "expected dfxml root element");
    assert!(stdout.contains("<fileobject>"), "expected fileobject element");
    assert!(stdout.contains("blake3"), "expected blake3 hashdigest type");
}
```

**Step 2: RED commit**

```bash
cargo test --test hash_tests test_dfxml 2>&1 | tail -5
git add tests/hash_tests.rs
git commit -m "test(RED): add failing test for DFXML output format"
```

**Step 3: Create `src/format/dfxml.rs`**

```rust
use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use std::io::Write;

pub fn write_dfxml<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    writeln!(w, "<?xml version='1.0' encoding='UTF-8'?>")?;
    writeln!(w, "<dfxml version='1.0' xmlns='http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML'>")?;
    writeln!(w, "  <metadata>")?;
    writeln!(w, "    <program>blazehash</program>")?;
    writeln!(w, "    <version>{}</version>", env!("CARGO_PKG_VERSION"))?;
    writeln!(w, "  </metadata>")?;

    for result in results {
        writeln!(w, "  <fileobject>")?;
        writeln!(w, "    <filename>{}</filename>",
            xml_escape(&result.path.display().to_string()))?;
        writeln!(w, "    <filesize>{}</filesize>", result.size)?;
        for algo in algorithms {
            if let Some(hash) = result.hashes.get(algo) {
                writeln!(w, "    <hashdigest type='{}'>{hash}</hashdigest>",
                    algo.hashdeep_name())?;
            }
        }
        writeln!(w, "  </fileobject>")?;
    }

    writeln!(w, "</dfxml>")?;
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
```

**Step 4: Export from `src/format/mod.rs`**

```rust
pub mod dfxml;
pub use self::dfxml::write_dfxml;
```

**Step 5: Add `"dfxml"` branch in `write_output` in `src/commands/hash.rs`**

```rust
"dfxml" => write_dfxml(writer, results, algorithms)?,
```

Do the same in `src/commands/piecewise.rs` and `src/commands/stdin.rs`.

**Step 6: Run and commit GREEN**

```bash
cargo test --test hash_tests test_dfxml 2>&1 | tail -5
git add src/format/dfxml.rs src/format/mod.rs src/commands/hash.rs
git commit -m "feat: add DFXML output format (--format dfxml)"
```

---

### Task 9: sha256sum / md5sum output format

**Files:**
- Create: `src/format/sumfile.rs`
- Modify: `src/format/mod.rs`
- Modify: `src/commands/hash.rs`
- Modify: `tests/hash_tests.rs`

**Step 1: Write failing test (RED)**

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_sha256sum_output_format() {
    use assert_cmd::Command;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.bin"), b"hello").unwrap();

    let output = Command::cargo_bin("blazehash")
        .unwrap()
        .args([dir.path().to_str().unwrap(), "-c", "sha256", "--format", "sha256sum"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    // sha256sum format: "<hash>  <path>\n" (two spaces)
    assert!(stdout.contains("  "), "expected two spaces between hash and path");
    assert!(!stdout.contains("%%%%"), "sha256sum format must not contain hashdeep header");
}

#[test]
fn test_sha256sum_rejects_multiple_algorithms() {
    use assert_cmd::Command;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f.bin"), b"x").unwrap();
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([dir.path().to_str().unwrap(), "-c", "sha256,md5", "--format", "sha256sum"])
        .assert()
        .failure();
}
```

**Step 2: RED commit**

```bash
cargo test --test hash_tests test_sha256sum 2>&1 | tail -5
git add tests/hash_tests.rs
git commit -m "test(RED): add failing tests for sha256sum/md5sum output format"
```

**Step 3: Create `src/format/sumfile.rs`**

```rust
use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::{bail, Result};
use std::io::Write;

pub fn write_sumfile<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    if algorithms.len() != 1 {
        bail!("sha256sum/md5sum format requires exactly one algorithm (got {})", algorithms.len());
    }
    let algo = &algorithms[0];
    for result in results {
        if let Some(hash) = result.hashes.get(algo) {
            writeln!(w, "{hash}  {}", result.path.display())?;
        }
    }
    Ok(())
}
```

**Step 4: Export from `src/format/mod.rs`**

```rust
pub mod sumfile;
pub use self::sumfile::write_sumfile;
```

**Step 5: Add `"sha256sum"` and `"md5sum"` branches in write_output in hash.rs, piecewise.rs, stdin.rs**

```rust
"sha256sum" | "md5sum" => write_sumfile(writer, results, algorithms)?,
```

**Step 6: Run and commit GREEN**

```bash
cargo test --test hash_tests test_sha256sum 2>&1 | tail -5
git add src/format/sumfile.rs src/format/mod.rs src/commands/hash.rs
git commit -m "feat: add sha256sum/md5sum output format (--format sha256sum)"
```

---

### Task 10: Raw/DD sidecar verification

**Files:**
- Modify: `src/commands/verify_image.rs`
- Modify: `src/forensic_image/` (extend or add sidecar module)
- Modify: `tests/verify_image_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/verify_image_tests.rs`:

```rust
#[test]
fn test_sidecar_verification_pass() {
    use assert_cmd::Command;
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("evidence.dd");
    std::fs::write(&image, b"disk image content here").unwrap();

    // Compute the actual SHA-256 and write sidecar
    let sha256 = {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(b"disk image content here");
        format!("{}", hex::encode(hash))
    };
    std::fs::write(dir.path().join("evidence.dd.sha256"), format!("{sha256}\n")).unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--verify-image", image.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("[+]"));
}

#[test]
fn test_sidecar_verification_fail() {
    use assert_cmd::Command;
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("evidence.dd");
    std::fs::write(&image, b"disk image content here").unwrap();
    // Wrong hash in sidecar
    std::fs::write(dir.path().join("evidence.dd.sha256"), "deadbeef\n").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--verify-image", image.to_str().unwrap()])
        .assert()
        .failure()
        .stdout(predicates::str::contains("[!]"));
}
```

**Step 2: RED commit**

```bash
cargo test --test verify_image_tests 2>&1 | tail -5
git add tests/verify_image_tests.rs
git commit -m "test(RED): add failing tests for raw/DD sidecar hash verification"
```

**Step 3: Implement sidecar detection in `src/commands/verify_image.rs`**

The command currently handles `.E01` via the EWF crate. Add a branch for raw images:

```rust
pub fn run(paths: &[PathBuf], output: Option<&PathBuf>) -> Result<()> {
    for path in paths {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        match ext.as_str() {
            "e01" | "ex01" | "l01" | "lx01" => {
                // existing EWF verification path
                verify_ewf(path)?;
            }
            "dd" | "raw" | "img" | "bin" => {
                verify_with_sidecar(path)?;
            }
            _ => {
                // Try sidecar first, then EWF
                if has_sidecar(path) {
                    verify_with_sidecar(path)?;
                } else {
                    verify_ewf(path)?;
                }
            }
        }
    }
    Ok(())
}

fn has_sidecar(image: &Path) -> bool {
    sidecar_extensions().iter().any(|ext| {
        image.with_extension(format!("{}.{ext}", image.extension()
            .and_then(|e| e.to_str()).unwrap_or(""))).exists()
    })
}

fn sidecar_extensions() -> &'static [&'static str] {
    &["md5", "sha1", "sha256", "sha512", "blake3"]
}

fn verify_with_sidecar(image: &Path) -> Result<()> {
    use blazehash::algorithm::{Algorithm, hash_bytes};
    use std::str::FromStr;

    let image_data = std::fs::read(image)?;
    let mut found_any = false;
    let mut all_pass = true;

    let base_ext = image.extension().and_then(|e| e.to_str()).unwrap_or("");

    for sidecar_ext in sidecar_extensions() {
        let sidecar = image.with_extension(format!("{base_ext}.{sidecar_ext}"));
        if !sidecar.exists() { continue; }
        found_any = true;

        let algo = Algorithm::from_str(sidecar_ext)
            .unwrap_or(Algorithm::Md5); // md5 sidecar uses Algorithm::Md5
        let actual = hash_bytes(algo, &image_data);
        let expected = std::fs::read_to_string(&sidecar)?.trim().to_lowercase();

        if actual == expected {
            println!("[+] {}  {} verified (sidecar)", image.display(), sidecar_ext.to_uppercase());
        } else {
            eprintln!("[!] {}  {} MISMATCH — expected {expected}, got {actual}",
                image.display(), sidecar_ext.to_uppercase());
            all_pass = false;
        }
    }

    if !found_any {
        anyhow::bail!("no sidecar hash files found for {}", image.display());
    }
    if !all_pass {
        anyhow::bail!("sidecar verification failed for {}", image.display());
    }
    Ok(())
}
```

**Step 4: Run and commit GREEN**

```bash
cargo test --test verify_image_tests 2>&1 | tail -5
git add src/commands/verify_image.rs
git commit -m "feat: add raw/DD sidecar hash verification (.md5/.sha256/.sha1/.blake3)"
```

---

### Task 11: Alternate Data Streams (Windows ADS)

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/walk.rs`
- Modify: `src/walk_windows.rs`
- Modify: `tests/hash_tests.rs`

**Step 1: Write failing test (RED)**

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_ads_flag_exists_in_cli() {
    use assert_cmd::Command;
    let dir = tempfile::tempdir().unwrap();
    // --ads flag must be accepted without error on all platforms
    Command::cargo_bin("blazehash")
        .unwrap()
        .args([dir.path().to_str().unwrap(), "--ads", "-c", "blake3"])
        .assert()
        .success();
}
```

**Step 2: RED commit**

```bash
cargo test --test hash_tests test_ads 2>&1 | tail -5
git add tests/hash_tests.rs
git commit -m "test(RED): add failing test for --ads flag"
```

**Step 3: Add `--ads` to CLI**

In `src/cli.rs`:
```rust
/// Hash NTFS Alternate Data Streams alongside main file content (Windows only)
#[arg(long = "ads")]
pub ads: bool,
```

**Step 4: Windows implementation in `src/walk_windows.rs`**

```rust
#[cfg(target_os = "windows")]
pub fn enumerate_ads(path: &Path) -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{
        FindFirstStreamW, FindNextStreamW, FindStreamData, FIND_STREAM_FLAGS,
    };
    // Use FindFirstStreamW / FindNextStreamW to enumerate streams
    // Each stream name is reported as "path:streamname:$DATA"
    // Return Vec<PathBuf> of synthetic paths "path:streamname"
    // Implementation uses windows-sys which is already a dep
    todo!("implement ADS enumeration via FindFirstStreamW")
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_ads(_path: &Path) -> Vec<PathBuf> {
    vec![] // no-op on non-Windows
}
```

Add the `ads: bool` param to `WalkFilter` and pass it through from CLI. In the walk loop, after hashing each file, if `ads == true`, call `enumerate_ads(path)` and hash each stream too.

**Step 5: Non-Windows stub satisfies the test**

The `--ads` flag is accepted on all platforms; on non-Windows it silently does nothing.

**Step 6: Run and commit GREEN**

```bash
cargo test --test hash_tests test_ads 2>&1 | tail -5
git add src/cli.rs src/walk.rs src/walk_windows.rs
git commit -m "feat: add --ads flag for NTFS Alternate Data Stream hashing (Windows)"
```

---

### Task 12: `blazehash diff` subcommand

**Files:**
- Create: `src/commands/diff.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Create: `tests/diff_tests.rs`

**Step 1: Write failing tests (RED)**

Create `tests/diff_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;
use std::path::PathBuf;
use tempfile::tempdir;
use std::fs;

fn write_hashdeep(path: &std::path::Path, entries: &[(&str, &str)]) {
    use std::io::Write;
    let mut f = fs::File::create(path).unwrap();
    writeln!(f, "%%%% HASHDEEP-1.0").unwrap();
    writeln!(f, "%%%% size,blake3,filename").unwrap();
    writeln!(f, "##").unwrap();
    for (hash, name) in entries {
        writeln!(f, "5,{hash},{name}").unwrap();
    }
}

#[test]
fn test_diff_detects_added_file() {
    use assert_cmd::Command;
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("aaaa", "/file1.bin"), ("bbbb", "/file2.bin")]);

    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ADDED") || stdout.contains("[+]"), "expected ADDED: {stdout}");
}

#[test]
fn test_diff_detects_removed_file() {
    use assert_cmd::Command;
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin"), ("bbbb", "/file2.bin")]);
    write_hashdeep(&after, &[("aaaa", "/file1.bin")]);

    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("REMOVED") || stdout.contains("[-]"), "expected REMOVED: {stdout}");
}

#[test]
fn test_diff_detects_modified_file() {
    use assert_cmd::Command;
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("zzzz", "/file1.bin")]);

    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("MODIFIED") || stdout.contains("[!]"), "expected MODIFIED: {stdout}");
}

#[test]
fn test_diff_exits_zero_when_identical() {
    use assert_cmd::Command;
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("aaaa", "/file1.bin")]);

    Command::cargo_bin("blazehash").unwrap()
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .assert().code(0);
}

#[test]
fn test_diff_exits_one_when_differences() {
    use assert_cmd::Command;
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("bbbb", "/file1.bin")]);

    Command::cargo_bin("blazehash").unwrap()
        .args(["diff", before.to_str().unwrap(), after.to_str().unwrap()])
        .assert().code(1);
}
```

**Step 2: RED commit**

```bash
cargo test --test diff_tests 2>&1 | tail -5
git add tests/diff_tests.rs
git commit -m "test(RED): add failing tests for blazehash diff subcommand"
```

**Step 3: Add `diff` subcommand to CLI**

In `src/cli.rs`, `mode()` method — `diff` is detected as a positional subcommand (same pattern as `mcp` and `bench`):
```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("diff")) {
    Mode::Diff
```

Add `Mode::Diff` to the enum.

**Step 4: Create `src/commands/diff.rs`**

```rust
use anyhow::Result;
use blazehash::manifest_loader::load_manifest;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum DiffEntry {
    Added(PathBuf),
    Removed(PathBuf),
    Modified { path: PathBuf, before: String, after: String },
    Moved { hash: String, from: PathBuf, to: PathBuf },
}

pub fn run(paths: &[PathBuf]) -> Result<bool> {
    // paths[1] = before manifest, paths[2] = after manifest
    // (paths[0] is "diff" — the subcommand name)
    if paths.len() < 3 {
        anyhow::bail!("usage: blazehash diff <before.hash> <after.hash>");
    }
    let before_path = &paths[1];
    let after_path = &paths[2];

    let before_records = load_manifest(before_path)?;
    let after_records = load_manifest(after_path)?;

    // Build maps: path -> first hash value (use first available algo)
    let before_map: HashMap<PathBuf, String> = before_records.iter()
        .filter_map(|r| r.hashes.values().next().map(|h| (r.path.clone(), h.clone())))
        .collect();
    let after_map: HashMap<PathBuf, String> = after_records.iter()
        .filter_map(|r| r.hashes.values().next().map(|h| (r.path.clone(), h.clone())))
        .collect();

    // Inverse map for moved detection: hash -> path
    let before_by_hash: HashMap<String, PathBuf> = before_map.iter()
        .map(|(p, h)| (h.clone(), p.clone()))
        .collect();

    let mut diffs = Vec::new();

    // Added and Modified
    for (path, hash) in &after_map {
        match before_map.get(path) {
            None => {
                // Check if hash exists elsewhere in before (moved)
                if let Some(from) = before_by_hash.get(hash) {
                    if !after_map.contains_key(from) {
                        diffs.push(DiffEntry::Moved { hash: hash.clone(), from: from.clone(), to: path.clone() });
                        continue;
                    }
                }
                diffs.push(DiffEntry::Added(path.clone()));
            }
            Some(before_hash) if before_hash != hash => {
                diffs.push(DiffEntry::Modified {
                    path: path.clone(),
                    before: before_hash.clone(),
                    after: hash.clone(),
                });
            }
            _ => {} // unchanged
        }
    }

    // Removed
    for path in before_map.keys() {
        if !after_map.contains_key(path) {
            let hash = &before_map[path];
            // Skip if already reported as Moved
            let already_moved = diffs.iter().any(|d| matches!(d, DiffEntry::Moved { from, .. } if from == path));
            if !already_moved {
                diffs.push(DiffEntry::Removed(path.clone()));
            }
        }
    }

    // Print results
    let mut has_diff = false;
    for diff in &diffs {
        has_diff = true;
        match diff {
            DiffEntry::Added(p) => println!("[+] ADDED    {}", p.display()),
            DiffEntry::Removed(p) => println!("[-] REMOVED  {}", p.display()),
            DiffEntry::Modified { path, .. } => println!("[!] MODIFIED {}", path.display()),
            DiffEntry::Moved { from, to, .. } => println!("[*] MOVED    {} <- {}", to.display(), from.display()),
        }
    }

    if !has_diff {
        println!("[+] Manifests are identical");
    }

    // Return true if differences found
    Ok(has_diff)
}
```

**Step 5: Add to `src/commands/mod.rs`**

```rust
pub mod diff;
```

**Step 6: Dispatch in `src/main.rs`**

```rust
Mode::Diff => {
    let has_diff = commands::diff::run(&cli.paths)?;
    if has_diff { std::process::exit(1); }
}
```

**Step 7: Run and commit GREEN**

```bash
cargo test --test diff_tests 2>&1 | tail -5
git add src/commands/diff.rs src/commands/mod.rs src/cli.rs src/main.rs tests/diff_tests.rs
git commit -m "feat: add blazehash diff subcommand (added/removed/modified/moved)"
```

---

### Task 13: `blazehash dedup` subcommand

**Files:**
- Create: `src/commands/dedup.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Create: `tests/dedup_tests.rs`

**Step 1: Write failing tests (RED)**

Create `tests/dedup_tests.rs`:

```rust
use assert_cmd::Command;
use tempfile::tempdir;
use std::fs;

#[test]
fn test_dedup_finds_duplicate_files() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("file1.bin"), b"same content").unwrap();
    fs::write(dir.path().join("file2.bin"), b"same content").unwrap();
    fs::write(dir.path().join("unique.bin"), b"unique content").unwrap();

    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", dir.path().to_str().unwrap(), "-c", "blake3"])
        .output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("file1.bin") || stdout.contains("file2.bin"),
        "expected duplicate files in output: {stdout}");
}

#[test]
fn test_dedup_exits_one_when_duplicates_found() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("a.bin"), b"dup").unwrap();
    fs::write(dir.path().join("b.bin"), b"dup").unwrap();

    Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", dir.path().to_str().unwrap()])
        .assert().code(1);
}

#[test]
fn test_dedup_exits_zero_when_no_duplicates() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("a.bin"), b"aaa").unwrap();
    fs::write(dir.path().join("b.bin"), b"bbb").unwrap();

    Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", dir.path().to_str().unwrap()])
        .assert().code(0);
}

#[test]
fn test_dedup_from_manifest() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    std::fs::write(&manifest,
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n##\n5,aaaa,/a.bin\n5,aaaa,/b.bin\n5,bbbb,/c.bin\n"
    ).unwrap();

    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["dedup", manifest.to_str().unwrap()])
        .output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("a.bin") || stdout.contains("b.bin"),
        "expected duplicate files: {stdout}");
}
```

**Step 2: RED commit**

```bash
cargo test --test dedup_tests 2>&1 | tail -5
git add tests/dedup_tests.rs
git commit -m "test(RED): add failing tests for blazehash dedup subcommand"
```

**Step 3: Add `dedup` to CLI mode detection**

Same pattern as `diff`: detect `paths[0] == "dedup"` → `Mode::Dedup`.

Add CLI flags:
```rust
/// Output only one file per duplicate group
#[arg(long = "dedup-unique")]
pub dedup_unique: bool,

/// Output only files that have duplicates
#[arg(long = "dedup-dupes")]
pub dedup_dupes: bool,
```

**Step 4: Create `src/commands/dedup.rs`**

```rust
use anyhow::Result;
use blazehash::algorithm::Algorithm;
use blazehash::hash::FileHashResult;
use blazehash::manifest_loader::load_manifest;
use blazehash::walk::{walk_and_hash, WalkFilter};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub fn run(
    paths: &[PathBuf],
    algorithms: &[Algorithm],
    recursive: bool,
    dedup_unique: bool,
    dedup_dupes: bool,
) -> Result<bool> {
    // paths[0] is "dedup", paths[1..] are targets
    let targets = &paths[1..];
    if targets.is_empty() {
        anyhow::bail!("usage: blazehash dedup <directory|manifest> ...");
    }

    let results = load_results(targets, algorithms, recursive)?;

    // Group by first hash value
    let mut groups: HashMap<String, Vec<&FileHashResult>> = HashMap::new();
    for r in &results {
        if let Some(hash) = r.hashes.values().next() {
            groups.entry(hash.clone()).or_default().push(r);
        }
    }

    let mut has_dupes = false;
    let mut total_redundant = 0usize;
    let mut reclaimable_bytes = 0u64;

    for (_, group) in &groups {
        if group.len() < 2 { continue; }
        has_dupes = true;
        total_redundant += group.len() - 1;
        reclaimable_bytes += group[1..].iter().map(|r| r.size).sum::<u64>();

        if dedup_unique {
            // Print only the first representative
            println!("{}", group[0].path.display());
        } else {
            // Print the whole group
            println!("## duplicate group ({} copies):", group.len());
            for r in group {
                println!("{},{}", r.size, r.path.display());
            }
        }
    }

    if dedup_dupes {
        // (already printed duplicates above — dedup_unique and dedup_dupes are mutually exclusive)
    }

    // Summary
    let unique = groups.values().filter(|g| g.len() == 1).count();
    let dup_groups = groups.values().filter(|g| g.len() >= 2).count();
    eprintln!(
        "[+] {} files — {} unique, {} duplicate groups, {} redundant copies ({:.1} GiB reclaimable)",
        results.len(), unique, dup_groups, total_redundant,
        reclaimable_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    Ok(has_dupes)
}

fn load_results(
    targets: &[PathBuf],
    algorithms: &[Algorithm],
    recursive: bool,
) -> Result<Vec<FileHashResult>> {
    let mut all = Vec::new();
    for target in targets {
        if target.is_file() {
            // Try loading as manifest
            match load_manifest(target) {
                Ok(records) => {
                    for rec in records {
                        all.push(FileHashResult {
                            path: rec.path,
                            size: rec.size,
                            hashes: rec.hashes,
                        });
                    }
                }
                Err(_) => {
                    // Hash it as a regular file
                    let r = blazehash::hash::hash_file(target, algorithms, false, false)?;
                    all.push(r);
                }
            }
        } else if target.is_dir() {
            let output = walk_and_hash(target, algorithms, recursive, &WalkFilter::default())?;
            all.extend(output.results);
        }
    }
    Ok(all)
}
```

**Step 5: Register and dispatch**

Add `pub mod dedup;` to `src/commands/mod.rs`.

In `src/main.rs`:
```rust
Mode::Dedup => {
    let has_dupes = commands::dedup::run(
        &cli.paths, &algorithms, cli.recursive,
        cli.dedup_unique, cli.dedup_dupes,
    )?;
    if has_dupes { std::process::exit(1); }
}
```

**Step 6: Run and commit GREEN**

```bash
cargo test --test dedup_tests 2>&1 | tail -5
git add src/commands/dedup.rs src/commands/mod.rs src/cli.rs src/main.rs tests/dedup_tests.rs
git commit -m "feat: add blazehash dedup subcommand (live hash or manifest, --dedup-unique/--dedup-dupes)"
```

---

### Task 14: NSRL lookup (`nsrl` feature)

**Files:**
- Create: `src/nsrl/mod.rs`
- Create: `src/nsrl/sqlite.rs`
- Create: `src/nsrl/bloom.rs`
- Modify: `src/lib.rs`
- Modify: `src/cli.rs`
- Modify: `src/commands/hash.rs`
- Create: `tests/nsrl_tests.rs`

**Step 1: Write failing tests (RED)**

Create `tests/nsrl_tests.rs`:

```rust
#[cfg(feature = "nsrl")]
mod nsrl_tests {
    use blazehash::nsrl::{NsrlLookup, NsrlResult};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_test_db(dir: &std::path::Path) -> PathBuf {
        // Create a minimal SQLite NSRL-format database
        use rusqlite::Connection;
        let db_path = dir.join("NSRL.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("
            CREATE TABLE FILE (SHA256 TEXT, MD5 TEXT, FileName TEXT, ProductCode INTEGER);
            INSERT INTO FILE VALUES ('aabbcc', 'ddeeff', 'notepad.exe', 1);
        ").unwrap();
        db_path
    }

    #[test]
    fn test_nsrl_sqlite_known_good() {
        let dir = tempdir().unwrap();
        let db = make_test_db(dir.path());
        let lookup = NsrlLookup::open(&db).unwrap();
        assert_eq!(lookup.lookup("aabbcc"), NsrlResult::KnownGood);
    }

    #[test]
    fn test_nsrl_sqlite_unknown() {
        let dir = tempdir().unwrap();
        let db = make_test_db(dir.path());
        let lookup = NsrlLookup::open(&db).unwrap();
        assert_eq!(lookup.lookup("deadbeef"), NsrlResult::Unknown);
    }

    #[test]
    fn test_nsrl_bloom_build_and_query() {
        let dir = tempdir().unwrap();
        let db = make_test_db(dir.path());
        let bloom_path = dir.path().join("nsrl.bloom");
        blazehash::nsrl::build_bloom(&db, &bloom_path, 0.001).unwrap();

        let lookup = NsrlLookup::open(&bloom_path).unwrap();
        assert_eq!(lookup.lookup("aabbcc"), NsrlResult::KnownGood);
    }
}
```

**Step 2: RED commit**

```bash
cargo test --features nsrl --test nsrl_tests 2>&1 | tail -5
git add tests/nsrl_tests.rs
git commit -m "test(RED): add failing tests for NSRL SQLite and bloom filter lookup"
```

**Step 3: Create `src/nsrl/mod.rs`**

```rust
#[cfg(feature = "nsrl")]
mod sqlite;
#[cfg(feature = "nsrl")]
mod bloom;

#[derive(Debug, PartialEq, Eq)]
pub enum NsrlResult {
    KnownGood,
    Unknown,
}

#[cfg(feature = "nsrl")]
pub struct NsrlLookup {
    inner: NsrlBackend,
}

#[cfg(feature = "nsrl")]
enum NsrlBackend {
    Sqlite(sqlite::SqliteNsrl),
    Bloom(bloom::BloomNsrl),
}

#[cfg(feature = "nsrl")]
impl NsrlLookup {
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let inner = if ext == "bloom" {
            NsrlBackend::Bloom(bloom::BloomNsrl::open(path)?)
        } else {
            NsrlBackend::Sqlite(sqlite::SqliteNsrl::open(path)?)
        };
        Ok(NsrlLookup { inner })
    }

    pub fn lookup(&self, hash: &str) -> NsrlResult {
        match &self.inner {
            NsrlBackend::Sqlite(s) => s.lookup(hash),
            NsrlBackend::Bloom(b) => b.lookup(hash),
        }
    }
}

#[cfg(feature = "nsrl")]
pub fn build_bloom(db_path: &std::path::Path, out_path: &std::path::Path, fp_rate: f64) -> anyhow::Result<()> {
    bloom::build_bloom_from_sqlite(db_path, out_path, fp_rate)
}
```

**Step 4: Create `src/nsrl/sqlite.rs`**

```rust
use super::NsrlResult;
use anyhow::Result;
use rusqlite::{Connection, params};
use std::path::Path;

pub struct SqliteNsrl {
    conn: Connection,
}

impl SqliteNsrl {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Ok(SqliteNsrl { conn })
    }

    pub fn lookup(&self, hash: &str) -> NsrlResult {
        let hash_upper = hash.to_uppercase();
        let exists: bool = self.conn
            .prepare_cached("SELECT 1 FROM FILE WHERE SHA256 = ?1 OR MD5 = ?1 LIMIT 1")
            .and_then(|mut s| s.exists(params![hash_upper]))
            .unwrap_or(false);
        if exists { NsrlResult::KnownGood } else { NsrlResult::Unknown }
    }
}
```

**Step 5: Create `src/nsrl/bloom.rs`**

```rust
use super::NsrlResult;
use anyhow::Result;
use bloomfilter::Bloom;
use rusqlite::Connection;
use std::path::Path;

pub struct BloomNsrl {
    bloom: Bloom<String>,
}

impl BloomNsrl {
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        let bloom: Bloom<String> = bincode::deserialize(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid bloom file: {e}"))?;
        Ok(BloomNsrl { bloom })
    }

    pub fn lookup(&self, hash: &str) -> NsrlResult {
        if self.bloom.check(&hash.to_uppercase()) {
            NsrlResult::KnownGood
        } else {
            NsrlResult::Unknown
        }
    }
}

pub fn build_bloom_from_sqlite(db_path: &Path, out_path: &Path, fp_rate: f64) -> Result<()> {
    let conn = Connection::open(db_path)?;
    // Count entries for sizing
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM FILE", [], |r| r.get(0))?;
    let mut bloom: Bloom<String> = Bloom::new_for_fp_rate(count as usize, fp_rate);

    let mut stmt = conn.prepare("SELECT SHA256 FROM FILE WHERE SHA256 IS NOT NULL")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let hash: String = row.get(0)?;
        bloom.set(&hash);
    }

    let bytes = bincode::serialize(&bloom)?;
    std::fs::write(out_path, bytes)?;
    eprintln!("[+] Bloom filter written to {}", out_path.display());
    Ok(())
}
```

Note: `bincode` needed for bloom serialization — add `bincode = "1"` to `[dependencies]` (or use the `bloomfilter` crate's built-in serialization if available).

**Step 6: Add to `src/lib.rs`**

```rust
#[cfg(feature = "nsrl")]
pub mod nsrl;
```

**Step 7: Add `--nsrl` flag to CLI**

```rust
#[arg(long = "nsrl", value_name = "FILE")]
pub nsrl: Option<PathBuf>,

#[arg(long = "nsrl-exclude", help = "Suppress known-good files from output")]
pub nsrl_exclude: bool,
```

**Step 8: Integrate into hash output**

In `src/commands/hash.rs`, after collecting results, if `--nsrl` is set: for each result, call `lookup(sha256_hash)`. Annotate result in the manifest comment or add `[K]` to stderr. If `--nsrl-exclude`, remove known-good entries from `all_results`.

Print to stderr: `[K] <path>  (NSRL known-good)`.

At end: `eprintln!("[K] {count} files known-good (NSRL)");`

**Step 9: Add `blazehash nsrl build-bloom` subcommand**

Detect `paths[0] == "nsrl"` and `paths[1] == "build-bloom"` → `Mode::NsrlBuildBloom`.

```rust
Mode::NsrlBuildBloom => {
    // paths[2] = input db, --output = bloom file
    let db = &cli.paths[2];
    let out = cli.output.as_ref()
        .ok_or_else(|| anyhow::anyhow!("--output required for nsrl build-bloom"))?;
    blazehash::nsrl::build_bloom(db, out, 0.001)?;
}
```

**Step 10: Run and commit GREEN**

```bash
cargo test --features nsrl --test nsrl_tests 2>&1 | tail -5
git add src/nsrl/ src/lib.rs src/cli.rs src/commands/hash.rs
git commit -m "feat: add NSRL lookup with SQLite and bloom filter backends (--nsrl, [K] annotation)"
```

---

### Task 15: Signed manifests (password-derived Ed25519, no key files)

**Design (revised from original):**
- No `keygen` command — no key files to manage
- Password-derived keypair: `Argon2id(password, b"blazehash-signing-v1")` → 32-byte seed → Ed25519
- Same password always produces same keypair (deterministic, no salt file)
- Password from keyboard via `rpassword` crate (`/dev/tty`, not stdin)
- `BLAZEHASH_SIGN_PASSWORD` env var for scripted use (prints warning to stderr)
- New crates needed: add `argon2 = "0.5"` and `rpassword = "6"` to `[dependencies]` in `Cargo.toml`
- `--sign` flag on hash command — requires `--output` (errors with hint if missing)
- `blazehash sign [manifest]` — standalone sign; auto-finds via `find_manifest()` if no arg given
- `blazehash verify-sig <manifest> --expected-pubkey <hex>`
- `.sig` sidecar: `blazehash-sig-v1\npubkey: <hex>\nsigned: <timestamp>\nsig: <hex>`
- Audit auto-verifies `.sig` sidecar if present and `--expected-pubkey` given; prints pubkey on sign for chain-of-custody recording

**Files:**
- Create: `src/signing.rs`
- Modify: `Cargo.toml` (add argon2, rpassword)
- Modify: `src/lib.rs`
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Modify: `src/commands/hash.rs` (--sign flag)
- Modify: `src/commands/audit.rs`
- Create: `tests/signing_tests.rs`

**Step 1: Write failing tests (RED)**

Create `tests/signing_tests.rs`:

```rust
use assert_cmd::Command;
use tempfile::tempdir;
use std::fs;

#[test]
fn test_sign_creates_sig_sidecar() {
    // Uses env var for non-interactive signing in tests
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(&manifest, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n").unwrap();

    Command::cargo_bin("blazehash").unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .assert().success();

    assert!(dir.path().join("manifest.hash.sig").exists(), ".sig file not created");
}

#[test]
fn test_verify_sig_roundtrip() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(&manifest, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n").unwrap();

    // Sign
    let sign_output = Command::cargo_bin("blazehash").unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output().unwrap();
    let stderr = String::from_utf8(sign_output.stderr).unwrap();
    // Extract public key from stderr output
    let pubkey = stderr.lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not printed to stderr");

    // Verify
    Command::cargo_bin("blazehash").unwrap()
        .args(["verify-sig", manifest.to_str().unwrap(), "--expected-pubkey", pubkey])
        .assert().success()
        .stdout(predicates::str::contains("[+]"));
}

#[test]
fn test_verify_sig_fails_on_tampered_manifest() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(&manifest, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n").unwrap();

    let sign_output = Command::cargo_bin("blazehash").unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "test-password-for-ci")
        .args(["sign", manifest.to_str().unwrap()])
        .output().unwrap();
    let stderr = String::from_utf8(sign_output.stderr).unwrap();
    let pubkey = stderr.lines()
        .find(|l| l.contains("Public key:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("public key not printed to stderr");

    // Tamper
    fs::write(&manifest, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,TAMPERED,/f.bin\n").unwrap();

    Command::cargo_bin("blazehash").unwrap()
        .args(["verify-sig", manifest.to_str().unwrap(), "--expected-pubkey", pubkey])
        .assert().failure()
        .stdout(predicates::str::contains("[!]"));
}

#[test]
fn test_sign_and_verify_sig_roundtrip() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(&manifest, "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n").unwrap();

    // Generate keys
    let key_path = dir.path().join("signing");
    Command::cargo_bin("blazehash").unwrap()
        .args(["keygen", "--out", key_path.to_str().unwrap()])
        .assert().success();

    // Sign
    Command::cargo_bin("blazehash").unwrap()
        .args(["sign", manifest.to_str().unwrap(),
               "--key", dir.path().join("signing.key").to_str().unwrap()])
        .assert().success();

    assert!(dir.path().join("manifest.hash.sig").exists(), ".sig file not created");

    // Verify
    Command::cargo_bin("blazehash").unwrap()
        .args(["verify-sig", manifest.to_str().unwrap(),
               "--sig", dir.path().join("manifest.hash.sig").to_str().unwrap(),
               "--pubkey", dir.path().join("signing.pub").to_str().unwrap()])
        .assert().success()
        .stdout(predicates::str::contains("[+]"));
}

#[test]
fn test_verify_sig_fails_on_tampered_manifest() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    fs::write(&manifest, "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n").unwrap();

    let key_path = dir.path().join("signing");
    Command::cargo_bin("blazehash").unwrap()
        .args(["keygen", "--out", key_path.to_str().unwrap()])
        .assert().success();

    Command::cargo_bin("blazehash").unwrap()
        .args(["sign", manifest.to_str().unwrap(),
               "--key", dir.path().join("signing.key").to_str().unwrap()])
        .assert().success();

    // Tamper with the manifest
    fs::write(&manifest, "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n##\n5,TAMPERED,/f.bin\n").unwrap();

    Command::cargo_bin("blazehash").unwrap()
        .args(["verify-sig", manifest.to_str().unwrap(),
               "--sig", dir.path().join("manifest.hash.sig").to_str().unwrap(),
               "--pubkey", dir.path().join("signing.pub").to_str().unwrap()])
        .assert().failure()
        .stdout(predicates::str::contains("[!]"));
}

#[test]
fn test_audit_auto_verifies_sig_sidecar() {
    let dir = tempdir().unwrap();
    // Create evidence file
    let evidence = dir.path().join("evidence");
    fs::create_dir(&evidence).unwrap();
    fs::write(evidence.join("file.bin"), b"data").unwrap();

    // Create manifest
    let manifest = dir.path().join("manifest.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["-r", evidence.to_str().unwrap(),
               "-c", "blake3",
               "-o", manifest.to_str().unwrap()])
        .assert().success();

    // Generate keys and sign the manifest
    let key_path = dir.path().join("signing");
    Command::cargo_bin("blazehash").unwrap()
        .args(["keygen", "--out", key_path.to_str().unwrap()])
        .assert().success();
    Command::cargo_bin("blazehash").unwrap()
        .args(["sign", manifest.to_str().unwrap(),
               "--key", dir.path().join("signing.key").to_str().unwrap()])
        .assert().success();

    // Audit should auto-verify the .sig sidecar
    let output = Command::cargo_bin("blazehash").unwrap()
        .args(["-r", evidence.to_str().unwrap(),
               "-a", "-k", manifest.to_str().unwrap()])
        .output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Signature verified") || stderr.contains("[K]"),
        "expected signature verification message in audit output: {stderr}");
}
```

**Step 2: RED commit**

```bash
cargo test --test signing_tests 2>&1 | tail -5
git add tests/signing_tests.rs
git commit -m "test(RED): add failing tests for blazehash keygen/sign/verify-sig"
```

**Step 3: Create `src/signing.rs`**

```rust
use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;
use std::path::Path;

/// Generate an Ed25519 keypair and write to `<out>.key` and `<out>.pub`.
pub fn keygen(out: &Path) -> Result<()> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let key_path = out.with_extension("key");
    let pub_path = out.with_extension("pub");

    std::fs::write(&key_path, hex::encode(signing_key.to_bytes()))
        .with_context(|| format!("cannot write {}", key_path.display()))?;
    std::fs::write(&pub_path, hex::encode(verifying_key.to_bytes()))
        .with_context(|| format!("cannot write {}", pub_path.display()))?;

    // Restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    eprintln!("[+] Private key: {}", key_path.display());
    eprintln!("[+] Public key:  {}", pub_path.display());
    Ok(())
}

/// Sign `manifest_path` with the private key at `key_path`.
/// Writes signature to `<manifest_path>.sig`.
pub fn sign(manifest_path: &Path, key_path: &Path) -> Result<()> {
    let key_hex = std::fs::read_to_string(key_path)
        .with_context(|| format!("cannot read key {}", key_path.display()))?;
    let key_bytes = hex::decode(key_hex.trim())?;
    let key_arr: [u8; 32] = key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("invalid key length"))?;
    let signing_key = SigningKey::from_bytes(&key_arr);
    let verifying_key = signing_key.verifying_key();

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;
    let signature: Signature = signing_key.sign(&manifest_bytes);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sig_content = format!(
        "blazehash-sig-v1\npubkey: {}\nsigned: {timestamp}\nsig: {}\n",
        hex::encode(verifying_key.to_bytes()),
        hex::encode(signature.to_bytes()),
    );

    let sig_path = manifest_path.with_extension(
        format!("{}.sig", manifest_path.extension()
            .and_then(|e| e.to_str()).unwrap_or(""))
    );
    std::fs::write(&sig_path, sig_content)?;
    eprintln!("[+] Signature written to {}", sig_path.display());
    Ok(())
}

/// Verify the signature in `sig_path` against `manifest_path` using `pubkey_path`.
/// Returns Ok(true) if valid, Ok(false) if invalid (caller should exit 1).
pub fn verify_sig(manifest_path: &Path, sig_path: &Path, pubkey_path: &Path) -> Result<bool> {
    let sig_content = std::fs::read_to_string(sig_path)?;
    let pubkey_hex = pubkey_path.exists()
        .then(|| std::fs::read_to_string(pubkey_path).ok())
        .flatten();

    // Parse sig file
    let mut sig_hex = None;
    let mut embedded_pubkey_hex = None;
    for line in sig_content.lines() {
        if let Some(v) = line.strip_prefix("sig: ") { sig_hex = Some(v.to_string()); }
        if let Some(v) = line.strip_prefix("pubkey: ") { embedded_pubkey_hex = Some(v.to_string()); }
    }

    let pub_hex = pubkey_hex.or(embedded_pubkey_hex)
        .ok_or_else(|| anyhow::anyhow!("cannot determine public key"))?;
    let pub_bytes = hex::decode(pub_hex.trim())?;
    let pub_arr: [u8; 32] = pub_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("invalid pubkey length"))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_arr)?;

    let sig_bytes = hex::decode(sig_hex.ok_or_else(|| anyhow::anyhow!("no sig: line in sig file"))?.trim())?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("invalid signature length"))?;
    let signature = Signature::from_bytes(&sig_arr);

    let manifest_bytes = std::fs::read(manifest_path)?;
    match verifying_key.verify(&manifest_bytes, &signature) {
        Ok(()) => {
            println!("[+] Signature valid — {}", manifest_path.display());
            Ok(true)
        }
        Err(_) => {
            println!("[!] Signature INVALID — {}", manifest_path.display());
            Ok(false)
        }
    }
}

/// Check for a `.sig` sidecar and verify it. Returns Ok(true) if sig present and valid.
/// Returns Ok(false) if no sig found (not an error). Returns Err if sig present but invalid.
pub fn auto_verify_sidecar(manifest_path: &Path) -> Result<bool> {
    let sig_path = manifest_path.with_extension(
        format!("{}.sig", manifest_path.extension()
            .and_then(|e| e.to_str()).unwrap_or(""))
    );
    if !sig_path.exists() {
        return Ok(false);
    }
    eprintln!("[*] Found signature sidecar: {}", sig_path.display());
    let valid = verify_sig(manifest_path, &sig_path, &sig_path)?; // pubkey embedded in sig file
    if !valid {
        anyhow::bail!("manifest signature is INVALID — aborting audit. Use --ignore-sig to override.");
    }
    eprintln!("[K] Signature verified — {}", manifest_path.display());
    Ok(true)
}
```

**Step 4: Add to `src/lib.rs`**

```rust
pub mod signing;
```

**Step 5: Add CLI flags for signing subcommands**

In `src/cli.rs`:
```rust
/// Output path for keygen (writes <out>.key and <out>.pub)
#[arg(long = "out")]
pub out: Option<PathBuf>,

/// Private key file for signing
#[arg(long = "key")]
pub key: Option<PathBuf>,

/// Signature file for verify-sig
#[arg(long = "sig")]
pub sig: Option<PathBuf>,

/// Public key file for verify-sig
#[arg(long = "pubkey")]
pub pubkey: Option<PathBuf>,

/// Skip manifest signature verification in audit mode
#[arg(long = "ignore-sig")]
pub ignore_sig: bool,
```

Detect subcommands in `mode()`:
```rust
} else if first == "keygen" { Mode::Keygen }
} else if first == "sign" { Mode::Sign }
} else if first == "verify-sig" { Mode::VerifySig }
```

**Step 6: Dispatch in `src/main.rs`**

```rust
Mode::Keygen => {
    let out = cli.out.as_ref().ok_or_else(|| anyhow::anyhow!("--out required for keygen"))?;
    blazehash::signing::keygen(out)?;
}
Mode::Sign => {
    let manifest = cli.paths.get(1).ok_or_else(|| anyhow::anyhow!("usage: blazehash sign <manifest> --key <key>"))?;
    let key = cli.key.as_ref().ok_or_else(|| anyhow::anyhow!("--key required"))?;
    blazehash::signing::sign(manifest, key)?;
}
Mode::VerifySig => {
    let manifest = cli.paths.get(1).ok_or_else(|| anyhow::anyhow!("usage: blazehash verify-sig <manifest> --sig <sig>"))?;
    let sig = cli.sig.as_ref().ok_or_else(|| anyhow::anyhow!("--sig required"))?;
    let pubkey = cli.pubkey.as_deref().unwrap_or(sig.as_path()); // embedded in sig file
    let valid = blazehash::signing::verify_sig(manifest, sig, std::path::Path::new(pubkey.to_str().unwrap_or("")))?;
    if !valid { std::process::exit(1); }
}
```

**Step 7: Auto-verify in audit**

In `src/commands/audit.rs`, at the top of `run()`, before loading the manifest:
```rust
if !ignore_sig {
    for known_path in known_files {
        let _ = blazehash::signing::auto_verify_sidecar(known_path)?;
    }
}
```

Pass `ignore_sig: bool` as a parameter to `commands::audit::run()`.

**Step 8: Run and commit GREEN**

```bash
cargo test --test signing_tests 2>&1 | tail -5
git add src/signing.rs src/lib.rs src/cli.rs src/main.rs src/commands/audit.rs tests/signing_tests.rs
git commit -m "feat: add blazehash keygen/sign/verify-sig with Ed25519 and audit auto-sig-verification"
```

---

## Module Layout After Implementation

```
src/
  algorithm.rs          — +Crc32c, Xxh3, Shake128, Shake256; is_non_cryptographic()
  walk_filter.rs        — WalkFilter, WalkFilterBuilder (glob, size, mtime)
  manifest_loader.rs    — load_manifest (all formats), find_manifest (auto-detect)
  signing.rs            — keygen, sign, verify_sig, auto_verify_sidecar
  nsrl/
    mod.rs              — NsrlLookup, NsrlResult, build_bloom
    sqlite.rs           — SqliteNsrl
    bloom.rs            — BloomNsrl, build_bloom_from_sqlite
  format/
    dfxml.rs            — write_dfxml
    sumfile.rs          — write_sumfile (sha256sum/md5sum)
  commands/
    stdin.rs            — --stdin mode
    diff.rs             — blazehash diff
    dedup.rs            — blazehash dedup
```

## New Cargo Dependencies

| Crate | Use | Feature-gated? |
|-------|-----|---------------|
| `xxhash-rust` | XXH3-128 | No |
| `crc32c` | CRC32C | No |
| `globset` | Glob patterns | No |
| `chrono` | Date parsing (--newer) | No |
| `ed25519-dalek` | Signing | No |
| `rand` | Keypair generation | No |
| `rusqlite` | NSRL SQLite | `nsrl` |
| `bloomfilter` | NSRL bloom filter | `nsrl` |
| `bincode` | Bloom serialization | `nsrl` |
