# blazehash Feature Batch 2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement 12 features: manifest merge/update/watch, remote manifest audit, entropy column, YARA scanning, VirusTotal lookup, SQLite output, HTML chain-of-custody report, NSRL .hsh hashset import, Docker layer hashing, and Parquet output.

**Architecture:** Layered build — new Cargo deps first, then independent features (entropy, SQLite, .hsh import), then compound features (merge, update, watch, remote audit, YARA, VT, report, Docker, Parquet) that compose existing infrastructure. Each feature is self-contained behind its own CLI subcommand or flag; no feature modifies existing behaviour.

**Tech Stack:** Rust. New direct deps: `notify` (cross-platform FSEvents/inotify/ReadDirectoryChanges), `ureq` (HTTP for remote manifest + VT API). New optional deps: `yara-x` (behind `yara` feature), `minijinja` (behind `report` feature), `parquet` + `arrow` (behind `parquet` feature), `oci-distribution` + `flate2` + `tar` (behind `docker` feature). Existing optional dep `rusqlite` already present (behind `nsrl` feature) — reuse it for SQLite output format too.

**TDD mandate:** Every task has a RED commit (failing tests only, all `todo!()` or missing symbols) then a GREEN commit (minimal implementation). Two commits per task, no exceptions. Confirm RED fails before writing GREEN.

---

## Task 1: New Cargo dependencies

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add direct deps**

Add to `[dependencies]` in `Cargo.toml`:

```toml
notify = "6"
ureq = { version = "2", features = ["json"] }
```

**Step 2: Add optional deps**

Add to `[dependencies]` (after existing optional deps):

```toml
yara-x = { version = "0.9", optional = true }
minijinja = { version = "2", optional = true }
parquet = { version = "53", optional = true }
arrow = { version = "53", optional = true }
oci-distribution = { version = "0.11", optional = true }
flate2 = { version = "1", optional = true }
tar = { version = "0.4", optional = true }
```

**Step 3: Add new feature flags**

In `[features]`:

```toml
yara    = ["dep:yara-x"]
report  = ["dep:minijinja"]
parquet = ["dep:parquet", "dep:arrow"]
docker  = ["dep:oci-distribution", "dep:flate2", "dep:tar"]
```

Note: `rusqlite` is already gated behind the `nsrl` feature. For SQLite output we will also require `nsrl` feature (same dep, no new gate needed — just expose `write_sqlite` when `rusqlite` is available).

**Step 4: Verify build**

```bash
cargo check --all-features
```
Expected: clean (no errors).

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add Cargo deps for feature batch 2 (notify, ureq, yara-x, minijinja, parquet, oci-distribution)"
```

---

## Task 2: Entropy column (`--entropy`)

Shannon entropy per file: `H = -Σ p_i * log2(p_i)` where `p_i` = fraction of bytes with value `i` across 256 values. Range 0.0 (all same byte) → 8.0 (perfectly uniform). Values above 7.2 indicate likely packed/encrypted content.

**Files:**
- Modify: `src/hash.rs` — add `entropy: Option<f64>` to `FileHashResult`; add `compute_entropy(bytes: &[u8]) -> f64` free function; populate when `--entropy` flag set
- Modify: `src/walk.rs` — thread `compute_entropy` flag through `walk_and_hash`
- Modify: `src/format/csv.rs` — emit optional `entropy` column
- Modify: `src/format/json.rs` + `src/format/mod.rs` — emit `entropy` field
- Modify: `src/cli.rs` — add `--entropy` flag; pass to walk
- Test: `tests/hash_tests.rs` — unit tests for `compute_entropy`
- Test: `tests/format_tests.rs` — entropy column in CSV/JSON

**Step 1: Write failing tests (RED)**

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_entropy_all_zeros() {
    let bytes = vec![0u8; 1024];
    let h = blazehash::hash::compute_entropy(&bytes);
    assert_eq!(h, 0.0, "all-zeros must have entropy 0.0");
}

#[test]
fn test_entropy_two_values_equal() {
    // 128 zeros + 128 ones → H = 1.0
    let mut bytes = vec![0u8; 128];
    bytes.extend(vec![1u8; 128]);
    let h = blazehash::hash::compute_entropy(&bytes);
    assert!((h - 1.0).abs() < 1e-9, "half-half binary must have entropy 1.0, got {h}");
}

#[test]
fn test_entropy_uniform_256() {
    // exactly one of each byte value → H ≈ 8.0
    let bytes: Vec<u8> = (0u8..=255).collect();
    let h = blazehash::hash::compute_entropy(&bytes);
    assert!((h - 8.0).abs() < 1e-9, "uniform 256-value must have entropy 8.0, got {h}");
}

#[test]
fn test_entropy_empty_is_zero() {
    let h = blazehash::hash::compute_entropy(&[]);
    assert_eq!(h, 0.0);
}
```

Add to `tests/format_tests.rs`:

```rust
#[test]
fn csv_entropy_column_present_when_set() {
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abc".to_string());
    let mut r = FileHashResult {
        path: PathBuf::from("/f.bin"),
        size: 10,
        hashes,
    };
    r.entropy = Some(7.9);
    let algos = vec![Algorithm::Blake3];
    let mut buf = Vec::new();
    write_csv(&mut buf, &[r], &algos).unwrap();
    let out = String::from_utf8(buf).unwrap();
    assert!(out.contains("entropy"), "header must contain entropy column");
    assert!(out.contains("7.9"), "data row must contain entropy value");
}

#[test]
fn json_entropy_field_present_when_set() {
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abc".to_string());
    let mut r = FileHashResult {
        path: PathBuf::from("/f.bin"),
        size: 10,
        hashes,
    };
    r.entropy = Some(3.5);
    let mut buf = Vec::new();
    write_json(&mut buf, &[r], &[Algorithm::Blake3]).unwrap();
    let out = String::from_utf8(buf).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v[0].get("entropy").is_some(), "JSON must include entropy field");
    assert_eq!(v[0]["entropy"], 3.5);
}
```

**Step 2: Run to confirm RED**

```bash
cargo test test_entropy_ csv_entropy_ json_entropy_ 2>&1 | grep -E "^error|FAILED|not found"
```
Expected: compile errors (`compute_entropy` not found, `FileHashResult` has no field `entropy`).

**Step 3: Implement (GREEN)**

In `src/hash.rs`, add after imports:

```rust
/// Compute Shannon entropy of `bytes` in bits per byte (range 0.0–8.0).
/// Returns 0.0 for empty input.
pub fn compute_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}
```

Add `entropy: Option<f64>` to `FileHashResult`:

```rust
pub struct FileHashResult {
    pub path: PathBuf,
    pub size: u64,
    pub hashes: HashMap<Algorithm, String>,
    pub entropy: Option<f64>,
}
```

Update every `FileHashResult { path, size, hashes }` literal in `src/` to also include `entropy: None`. Use `grep -rn "FileHashResult {" src/` to find all sites.

In `src/format/csv.rs`: if any result has `entropy.is_some()`, append `entropy` header column and each row's value (or empty string if `None`).

In `src/format/json.rs`: if `entropy.is_some()`, emit `"entropy": <value>` in the JSON object.

In `src/cli.rs`: add `#[arg(long)] entropy: bool,` to `Cli`. In `Mode::Hash` dispatch, pass flag through to `walk_and_hash`. In `walk_and_hash`, after building `bytes` buffer, if `entropy` flag: call `compute_entropy(&bytes)` and set `result.entropy = Some(h)`.

**Step 4: Run to confirm GREEN**

```bash
cargo test test_entropy_ csv_entropy_ json_entropy_
```
Expected: all pass.

**Step 5: RED commit then GREEN commit**

```bash
# Already done in steps above — ensure two separate commits:
# RED: git commit -m "test(RED): add failing tests for --entropy column"
# GREEN: git commit -m "feat: add --entropy Shannon entropy column to hash output"
```

---

## Task 3: SQLite output format (`--format sqlite`)

Write hashing results to a `.db` SQLite file with table `files(path TEXT PRIMARY KEY, size INTEGER, entropy REAL, <algo> TEXT, ...)`. Requires `nsrl` feature (reuses existing `rusqlite` dep).

**Files:**
- Create: `src/format/sqlite.rs`
- Modify: `src/format/mod.rs` — add `write_sqlite` export
- Modify: `src/cli.rs` — add `Sqlite` variant to `OutputFormat` enum; add note that `--format sqlite` requires `--features nsrl`
- Test: `tests/format_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/format_tests.rs` (behind `#[cfg(feature = "nsrl")]`):

```rust
#[cfg(feature = "nsrl")]
#[test]
fn sqlite_output_queryable() {
    use blazehash::format::write_sqlite;
    use std::collections::HashMap;
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use std::path::PathBuf;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("out.db");

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "deadbeef".to_string());
    let result = FileHashResult {
        path: PathBuf::from("/evidence/doc.pdf"),
        size: 42,
        hashes,
        entropy: Some(6.5),
    };

    write_sqlite(&db_path, &[result], &[Algorithm::Blake3]).unwrap();
    assert!(db_path.exists());

    // Query it back
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let (path, size, blake3, entropy): (String, u64, String, f64) = conn
        .query_row(
            "SELECT path, size, blake3, entropy FROM files WHERE path = '/evidence/doc.pdf'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(path, "/evidence/doc.pdf");
    assert_eq!(size, 42);
    assert_eq!(blake3, "deadbeef");
    assert!((entropy - 6.5).abs() < 1e-6);
}
```

**Step 2: Confirm RED**

```bash
cargo test --features nsrl sqlite_output_queryable 2>&1 | grep -E "FAILED|error"
```
Expected: `write_sqlite` not found.

**Step 3: Implement (GREEN)**

Create `src/format/sqlite.rs`:

```rust
#[cfg(feature = "nsrl")]
use crate::algorithm::Algorithm;
#[cfg(feature = "nsrl")]
use crate::hash::FileHashResult;
#[cfg(feature = "nsrl")]
use anyhow::Result;
#[cfg(feature = "nsrl")]
use std::path::Path;

#[cfg(feature = "nsrl")]
pub fn write_sqlite(path: &Path, results: &[FileHashResult], algos: &[Algorithm]) -> Result<()> {
    let conn = rusqlite::Connection::open(path)?;
    // Build CREATE TABLE with one column per algorithm + entropy
    let algo_cols: Vec<String> = algos.iter().map(|a| format!("{} TEXT", a.name())).collect();
    let create = format!(
        "CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, size INTEGER, entropy REAL, {})",
        algo_cols.join(", ")
    );
    conn.execute_batch(&create)?;

    let placeholders: Vec<String> = (0..algos.len() + 3).map(|i| format!("?{}", i + 1)).collect();
    let insert = format!(
        "INSERT OR REPLACE INTO files (path, size, entropy, {}) VALUES ({})",
        algos.iter().map(|a| a.name()).collect::<Vec<_>>().join(", "),
        placeholders.join(", ")
    );

    let mut stmt = conn.prepare(&insert)?;
    for r in results {
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![
            Box::new(r.path.to_string_lossy().into_owned()),
            Box::new(r.size as i64),
            Box::new(r.entropy),
        ];
        for algo in algos {
            params.push(Box::new(r.hashes.get(algo).cloned().unwrap_or_default()));
        }
        stmt.execute(rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())))?;
    }
    Ok(())
}
```

Export in `src/format/mod.rs`:

```rust
#[cfg(feature = "nsrl")]
pub mod sqlite;
#[cfg(feature = "nsrl")]
pub use sqlite::write_sqlite;
```

Add `Sqlite` to `OutputFormat` enum in `src/cli.rs`:

```rust
Sqlite,  // requires --features nsrl
```

In `src/main.rs` dispatch: when `OutputFormat::Sqlite`, call `write_sqlite(&output_path, &results, &algos)?`.

**Step 4: Confirm GREEN**

```bash
cargo test --features nsrl sqlite_output_queryable
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing test for --format sqlite"
git commit -m "feat: add --format sqlite output (requires nsrl feature)"
```

---

## Task 4: NSRL `.hsh` hashset import

NIST NSRL ships flat pipe-delimited `.hsh` files with format:
```
"SHA-1"|"MD5"|"CRC32"|"FileName"|"FileSize"|"ProductCode"|"OpSystemCode"|"SpecialCode"
```
First line is a header. We want to load SHA-1 and/or MD5 values into a `HashSet<String>` (lowercased hex) for use with `--nsrl`.

**Files:**
- Modify: `src/nsrl/mod.rs` — add `load_hsh(path: &Path) -> Result<HashSet<String>>`
- Modify: `src/cli.rs` — add `--nsrl-hsh <FILE>` flag alongside `--nsrl`
- Test: `tests/nsrl_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/nsrl_tests.rs`:

```rust
#[cfg(feature = "nsrl")]
#[test]
fn test_load_hsh_parses_sha1() {
    use blazehash::nsrl::load_hsh;
    let dir = tempfile::tempdir().unwrap();
    let hsh = dir.path().join("NSRLFile.txt");
    std::fs::write(&hsh,
        "\"SHA-1\"|\"MD5\"|\"CRC32\"|\"FileName\"|\"FileSize\"|\"ProductCode\"|\"OpSystemCode\"|\"SpecialCode\"\n\
         \"AABBCCDDEEFF00112233445566778899AABBCCDD\"|\"00112233445566778899AABBCCDDEEFF\"|\"DEADBEEF\"|\"notepad.exe\"|\"69120\"|\"1\"|\"WIN\"|\"M\"\n"
    ).unwrap();
    let set = load_hsh(&hsh).unwrap();
    assert!(set.contains("aabbccddeeff00112233445566778899aabbccdd"),
        "SHA-1 should be in set (lowercased)");
}

#[cfg(feature = "nsrl")]
#[test]
fn test_load_hsh_empty_file() {
    use blazehash::nsrl::load_hsh;
    let dir = tempfile::tempdir().unwrap();
    let hsh = dir.path().join("empty.hsh");
    std::fs::write(&hsh,
        "\"SHA-1\"|\"MD5\"|\"CRC32\"|\"FileName\"|\"FileSize\"|\"ProductCode\"|\"OpSystemCode\"|\"SpecialCode\"\n"
    ).unwrap();
    let set = load_hsh(&hsh).unwrap();
    assert!(set.is_empty());
}
```

**Step 2: Confirm RED**

```bash
cargo test --features nsrl test_load_hsh_ 2>&1 | grep -E "FAILED|error"
```

**Step 3: Implement (GREEN)**

In `src/nsrl/mod.rs`, add:

```rust
/// Load a NIST NSRL flat `.hsh` file, returning all SHA-1 hashes (lowercased).
/// Format: pipe-delimited, first column is quoted SHA-1, first line is header.
pub fn load_hsh(path: &std::path::Path) -> anyhow::Result<std::collections::HashSet<String>> {
    use std::io::{BufRead, BufReader};
    let f = std::fs::File::open(path)?;
    let mut set = std::collections::HashSet::new();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        if i == 0 { continue; } // skip header
        // Fields are pipe-delimited, each field optionally quoted
        let sha1 = line.split('|').next().unwrap_or("").trim_matches('"').to_lowercase();
        if sha1.len() == 40 { // SHA-1 hex = 40 chars
            set.insert(sha1);
        }
    }
    Ok(set)
}
```

In `src/cli.rs`, add `--nsrl-hsh <FILE>` to `Cli`:

```rust
#[cfg(feature = "nsrl")]
#[arg(long, value_name = "FILE", help = "NIST NSRL .hsh flat hashset file")]
pub nsrl_hsh: Option<std::path::PathBuf>,
```

In dispatch (`src/main.rs`), when `nsrl_hsh` is set: call `load_hsh`, merge the resulting `HashSet` into the NSRL filter alongside any SQLite-loaded hashes.

**Step 4: Confirm GREEN**

```bash
cargo test --features nsrl test_load_hsh_
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing tests for NSRL .hsh flat hashset import"
git commit -m "feat(nsrl): add load_hsh() and --nsrl-hsh flag for NIST flat hashset files"
```

---

## Task 5: `blazehash merge`

Combine two or more manifests into one. Load each with the existing `manifest_loader::load_manifest`, union all records. If the same path appears in multiple manifests, the last one wins (consistent with append semantics). Write the merged result using the existing format writers. Optionally sign with `--sign`.

**Files:**
- Create: `src/commands/merge.rs`
- Modify: `src/commands/mod.rs` — add `pub mod merge`
- Modify: `src/cli.rs` — add `Merge` to `Mode`; add `--merge-inputs` args
- Modify: `src/main.rs` — dispatch `Mode::Merge`
- Test: `tests/merge_tests.rs`

**Step 1: Write failing tests (RED)**

Create `tests/merge_tests.rs`:

```rust
use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_merge_two_non_overlapping_manifests() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.hash");
    let b = dir.path().join("b.hash");
    let out = dir.path().join("merged.hash");

    fs::write(&a, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,aaa,/a.bin\n").unwrap();
    fs::write(&b, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n6,bbb,/b.bin\n").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["merge", a.to_str().unwrap(), b.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert()
        .success();

    let merged = fs::read_to_string(&out).unwrap();
    assert!(merged.contains("/a.bin"), "merged should contain /a.bin");
    assert!(merged.contains("/b.bin"), "merged should contain /b.bin");
}

#[test]
fn test_merge_last_write_wins_on_duplicate_path() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.hash");
    let b = dir.path().join("b.hash");
    let out = dir.path().join("merged.hash");

    // Same path /dup.bin in both, different hashes
    fs::write(&a, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,oldold,/dup.bin\n").unwrap();
    fs::write(&b, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,newnew,/dup.bin\n").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["merge", a.to_str().unwrap(), b.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .assert()
        .success();

    let merged = fs::read_to_string(&out).unwrap();
    assert!(merged.contains("newnew"), "last manifest's hash should win");
    assert!(!merged.contains("oldold"), "earlier hash should be overwritten");
}

#[test]
fn test_merge_requires_output_flag() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.hash");
    fs::write(&a, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,aaa,/a.bin\n").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["merge", a.to_str().unwrap()])
        .assert()
        .failure(); // needs at least 2 inputs and -o
}
```

**Step 2: Confirm RED**

```bash
cargo test --test merge_tests 2>&1 | grep -E "FAILED|error"
```
Expected: `merge` subcommand not found / compile error.

**Step 3: Implement (GREEN)**

Create `src/commands/merge.rs`:

```rust
use crate::manifest_loader::load_manifest;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct MergeArgs {
    pub inputs: Vec<PathBuf>,
    pub output: PathBuf,
}

pub fn run_merge(args: MergeArgs) -> Result<()> {
    if args.inputs.len() < 2 {
        bail!("merge requires at least 2 input manifests");
    }

    // last-write-wins by path
    let mut by_path: HashMap<PathBuf, crate::manifest_loader::ManifestRecord> = HashMap::new();
    for input in &args.inputs {
        for record in load_manifest(input)? {
            by_path.insert(record.path.clone(), record);
        }
    }

    let mut records: Vec<_> = by_path.into_values().collect();
    records.sort_by(|a, b| a.path.cmp(&b.path));

    write_merged(&args.output, &records)
}

fn write_merged(out: &Path, records: &[crate::manifest_loader::ManifestRecord]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(out)?;
    writeln!(f, "%%%% BLAZEHASH-1.0")?;
    writeln!(f, "%%%% size,blake3,filename")?;
    writeln!(f, "##")?;
    for r in records {
        let hash = r.hashes.values().next().map(|s| s.as_str()).unwrap_or("");
        writeln!(f, "{},{},{}", r.size, hash, r.path.display())?;
    }
    Ok(())
}
```

Add `pub mod merge;` to `src/commands/mod.rs`.

In `src/cli.rs`, add `Merge` to `Mode` and handle `merge` subcommand parsing (inputs as `Vec<PathBuf>`, `-o` required).

In `src/main.rs`, dispatch `Mode::Merge` to `commands::merge::run_merge(...)`.

**Step 4: Confirm GREEN**

```bash
cargo test --test merge_tests
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing tests for blazehash merge"
git commit -m "feat: add blazehash merge subcommand"
```

---

## Task 6: `blazehash update` (incremental)

Re-hash only new or changed files; leave unchanged entries intact. "Changed" is determined by comparing file size — if size matches the manifest record, skip re-hash. New files (not in manifest) are hashed and appended. Deleted files (in manifest but not on disk) are removed from the output. Writes updated manifest to the same path (or `-o` if specified).

**Files:**
- Create: `src/commands/update.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs` — `Update` variant, `update <manifest> <path>`
- Modify: `src/main.rs`
- Test: `tests/update_tests.rs`

**Step 1: Write failing tests (RED)**

Create `tests/update_tests.rs`:

```rust
use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_update_appends_new_file() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    let existing = dir.path().join("existing.bin");
    let new_file = dir.path().join("new.bin");

    fs::write(&existing, b"hello").unwrap();
    // Create initial manifest with only existing.bin
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-o", manifest.to_str().unwrap(), existing.to_str().unwrap()])
        .assert()
        .success();

    // Add new_file
    fs::write(&new_file, b"world").unwrap();

    // Update — should append new_file
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["update", manifest.to_str().unwrap(), dir.path().to_str().unwrap()])
        .assert()
        .success();

    let contents = fs::read_to_string(&manifest).unwrap();
    assert!(contents.contains("new.bin"), "update should append new.bin");
    assert!(contents.contains("existing.bin"), "update should keep existing.bin");
}

#[test]
fn test_update_removes_deleted_file() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    let f1 = dir.path().join("f1.bin");
    let f2 = dir.path().join("f2.bin");

    fs::write(&f1, b"aaa").unwrap();
    fs::write(&f2, b"bbb").unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-r", "-o", manifest.to_str().unwrap(), dir.path().to_str().unwrap()])
        .assert()
        .success();

    fs::remove_file(&f2).unwrap();

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["update", manifest.to_str().unwrap(), dir.path().to_str().unwrap()])
        .assert()
        .success();

    let contents = fs::read_to_string(&manifest).unwrap();
    assert!(!contents.contains("f2.bin"), "deleted file should be removed from manifest");
}

#[test]
fn test_update_rehashes_changed_file() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    let f = dir.path().join("data.bin");

    fs::write(&f, b"original").unwrap(); // 8 bytes

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["-o", manifest.to_str().unwrap(), f.to_str().unwrap()])
        .assert()
        .success();

    let before = fs::read_to_string(&manifest).unwrap();

    // Change file (different size → triggers re-hash)
    fs::write(&f, b"changed content here").unwrap(); // 20 bytes

    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["update", manifest.to_str().unwrap(), dir.path().to_str().unwrap()])
        .assert()
        .success();

    let after = fs::read_to_string(&manifest).unwrap();
    assert_ne!(before, after, "manifest should change after file content change");
    assert!(after.contains("20,"), "updated manifest should reflect new size");
}
```

**Step 2: Confirm RED**

```bash
cargo test --test update_tests 2>&1 | grep -E "FAILED|error"
```

**Step 3: Implement (GREEN)**

Create `src/commands/update.rs`:

```rust
use crate::algorithm::Algorithm;
use crate::hash::hash_file;
use crate::manifest_loader::{load_manifest, ManifestRecord};
use crate::walk_filter::WalkFilter;
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct UpdateArgs {
    pub manifest: PathBuf,
    pub path: PathBuf,
    pub algos: Vec<Algorithm>,
    pub output: PathBuf, // default = same as manifest
}

pub fn run_update(args: UpdateArgs) -> Result<()> {
    // Load existing manifest into a map keyed by canonical path
    let existing: HashMap<PathBuf, ManifestRecord> = load_manifest(&args.manifest)?
        .into_iter()
        .map(|r| (r.path.clone(), r))
        .collect();

    // Walk the target path to discover current files
    let filter = WalkFilter::default();
    let mut updated: HashMap<PathBuf, ManifestRecord> = HashMap::new();

    for entry in walkdir::WalkDir::new(&args.path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let fpath = entry.path().to_path_buf();
        let meta = std::fs::metadata(&fpath)?;
        let fsize = meta.len();

        if let Some(rec) = existing.get(&fpath) {
            if rec.size == fsize {
                // Unchanged — keep existing record
                updated.insert(fpath, rec.clone());
                continue;
            }
        }

        // New or changed — re-hash
        let result = hash_file(&fpath, &args.algos, false)?;
        updated.insert(fpath.clone(), ManifestRecord {
            path: fpath,
            size: result.size,
            hashes: result.hashes.into_iter()
                .map(|(k, v)| (k.name().to_string(), v))
                .collect(),
        });
    }

    // Write updated manifest
    write_manifest(&args.output, &updated)
}

fn write_manifest(out: &Path, records: &HashMap<PathBuf, ManifestRecord>) -> Result<()> {
    use std::io::Write;
    let mut sorted: Vec<_> = records.values().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut f = std::fs::File::create(out)?;
    writeln!(f, "%%%% BLAZEHASH-1.0")?;
    writeln!(f, "%%%% size,blake3,filename")?;
    writeln!(f, "##")?;
    for r in sorted {
        let hash = r.hashes.values().next().map(|s| s.as_str()).unwrap_or("");
        writeln!(f, "{},{},{}", r.size, hash, r.path.display())?;
    }
    Ok(())
}
```

**Step 4: Confirm GREEN**

```bash
cargo test --test update_tests
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing tests for blazehash update (incremental)"
git commit -m "feat: add blazehash update subcommand for incremental manifest refresh"
```

---

## Task 7: `blazehash watch`

Monitor a directory against a baseline manifest. Uses the `notify` crate for cross-platform FSEvents (macOS), inotify (Linux), ReadDirectoryChangesW (Windows). On any file system event, re-hash the changed file and compare against baseline. Emit `[+] path` for new files, `[!] path` for modified, `[-] path` for deleted.

**Files:**
- Create: `src/commands/watch.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs` — `Watch` variant; `watch <path> <manifest>`
- Modify: `src/main.rs`
- Test: `tests/watch_tests.rs`

**Step 1: Write failing tests (RED)**

Create `tests/watch_tests.rs`:

```rust
// Watch is an interactive daemon; we test the core detection logic, not the event loop.
use blazehash::watch::check_file_against_baseline;
use blazehash::manifest_loader::ManifestRecord;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn test_check_new_file_not_in_baseline() {
    let dir = tempdir().unwrap();
    let f = dir.path().join("new.bin");
    std::fs::write(&f, b"content").unwrap();
    let baseline: HashMap<PathBuf, ManifestRecord> = HashMap::new();
    let status = check_file_against_baseline(&f, &baseline, &[blazehash::algorithm::Algorithm::Blake3]).unwrap();
    assert_eq!(status, blazehash::watch::ChangeStatus::New);
}

#[test]
fn test_check_unchanged_file_matches_baseline() {
    let dir = tempdir().unwrap();
    let f = dir.path().join("file.bin");
    std::fs::write(&f, b"content").unwrap();
    let mut hashes = HashMap::new();
    // blake3 of b"content"
    let h = blazehash::hash::hash_file(&f, &[blazehash::algorithm::Algorithm::Blake3], false).unwrap();
    let blake3_hash = h.hashes[&blazehash::algorithm::Algorithm::Blake3].clone();
    hashes.insert("blake3".to_string(), blake3_hash);
    let mut baseline = HashMap::new();
    baseline.insert(f.clone(), blazehash::manifest_loader::ManifestRecord {
        path: f.clone(), size: 7, hashes,
    });
    let status = check_file_against_baseline(&f, &baseline, &[blazehash::algorithm::Algorithm::Blake3]).unwrap();
    assert_eq!(status, blazehash::watch::ChangeStatus::Unchanged);
}

#[test]
fn test_check_modified_file_differs_from_baseline() {
    let dir = tempdir().unwrap();
    let f = dir.path().join("file.bin");
    std::fs::write(&f, b"modified").unwrap();
    let mut hashes = HashMap::new();
    hashes.insert("blake3".to_string(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
    let mut baseline = HashMap::new();
    baseline.insert(f.clone(), blazehash::manifest_loader::ManifestRecord {
        path: f.clone(), size: 8, hashes,
    });
    let status = check_file_against_baseline(&f, &baseline, &[blazehash::algorithm::Algorithm::Blake3]).unwrap();
    assert_eq!(status, blazehash::watch::ChangeStatus::Modified);
}
```

**Step 2: Confirm RED**

```bash
cargo test --test watch_tests 2>&1 | grep -E "FAILED|error"
```

**Step 3: Implement (GREEN)**

Create `src/watch.rs`:

```rust
use crate::algorithm::Algorithm;
use crate::hash::hash_file;
use crate::manifest_loader::ManifestRecord;
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum ChangeStatus {
    New,
    Modified,
    Unchanged,
}

/// Compare a single file on disk against a baseline manifest.
pub fn check_file_against_baseline(
    path: &Path,
    baseline: &HashMap<PathBuf, ManifestRecord>,
    algos: &[Algorithm],
) -> Result<ChangeStatus> {
    let result = hash_file(path, algos, false)?;
    match baseline.get(path) {
        None => Ok(ChangeStatus::New),
        Some(rec) => {
            for algo in algos {
                let name = algo.name();
                if let (Some(expected), Some(actual)) =
                    (rec.hashes.get(name), result.hashes.get(algo))
                {
                    if expected != actual {
                        return Ok(ChangeStatus::Modified);
                    }
                }
            }
            Ok(ChangeStatus::Unchanged)
        }
    }
}
```

Create `src/commands/watch.rs` with the `notify`-based event loop:

```rust
use crate::algorithm::Algorithm;
use crate::manifest_loader::{load_manifest, ManifestRecord};
use crate::watch::{check_file_against_baseline, ChangeStatus};
use anyhow::Result;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;

pub struct WatchArgs {
    pub path: PathBuf,
    pub manifest: PathBuf,
    pub algos: Vec<Algorithm>,
}

pub fn run_watch(args: WatchArgs) -> Result<()> {
    let records = load_manifest(&args.manifest)?;
    let baseline: HashMap<PathBuf, ManifestRecord> =
        records.into_iter().map(|r| (r.path.clone(), r)).collect();

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(&args.path, RecursiveMode::Recursive)?;

    eprintln!("[*] Watching {} against {}", args.path.display(), args.manifest.display());
    eprintln!("[*] Press Ctrl+C to stop.");

    for event in rx {
        let event = event?;
        match event.kind {
            EventKind::Remove(_) => {
                for p in &event.paths {
                    eprintln!("[-] {}", p.display());
                }
            }
            EventKind::Create(_) | EventKind::Modify(_) => {
                for p in &event.paths {
                    if !p.is_file() { continue; }
                    match check_file_against_baseline(p, &baseline, &args.algos) {
                        Ok(ChangeStatus::New)      => eprintln!("[+] {}", p.display()),
                        Ok(ChangeStatus::Modified) => eprintln!("[!] {}", p.display()),
                        Ok(ChangeStatus::Unchanged) => {}
                        Err(e) => eprintln!("[?] {} — {e}", p.display()),
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
```

Export `pub mod watch;` in `src/lib.rs`. Wire up CLI and dispatch.

**Step 4: Confirm GREEN**

```bash
cargo test --test watch_tests
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing tests for watch baseline comparison logic"
git commit -m "feat: add blazehash watch subcommand (notify-based FSEvents/inotify)"
```

---

## Task 8: Remote manifest for `blazehash audit`

When the manifest argument to `audit` starts with `http://` or `https://`, fetch it into a temporary file via `ureq`, then proceed with the normal audit flow.

**Files:**
- Modify: `src/manifest_loader.rs` — add `fetch_remote_manifest(url: &str) -> Result<tempfile::NamedTempFile>`
- Modify: `src/commands/audit.rs` — detect URL, call `fetch_remote_manifest` before loading
- Test: `tests/manifest_loader_tests.rs` — unit test URL detection; integration test uses a `std::net::TcpListener` serving a fixture manifest

**Step 1: Write failing tests (RED)**

Add to `tests/manifest_loader_tests.rs`:

```rust
#[test]
fn test_is_remote_url_http() {
    assert!(blazehash::manifest_loader::is_remote_url("http://example.com/manifest.hash"));
}

#[test]
fn test_is_remote_url_https() {
    assert!(blazehash::manifest_loader::is_remote_url("https://example.com/manifest.hash"));
}

#[test]
fn test_is_remote_url_local_path() {
    assert!(!blazehash::manifest_loader::is_remote_url("/tmp/manifest.hash"));
    assert!(!blazehash::manifest_loader::is_remote_url("manifest.hash"));
}

#[test]
fn test_fetch_remote_manifest_from_local_server() {
    use std::net::TcpListener;
    use std::io::Write;
    use std::thread;

    let body = "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                body.len(), body
            );
            stream.write_all(response.as_bytes()).ok();
        }
    });

    let tmp = blazehash::manifest_loader::fetch_remote_manifest(
        &format!("http://127.0.0.1:{port}/manifest.hash")
    ).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(content.contains("BLAZEHASH-1.0"));
}
```

**Step 2: Confirm RED**

```bash
cargo test --test manifest_loader_tests test_is_remote_ test_fetch_remote_ 2>&1 | grep -E "FAILED|error"
```

**Step 3: Implement (GREEN)**

In `src/manifest_loader.rs`:

```rust
pub fn is_remote_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

pub fn fetch_remote_manifest(url: &str) -> anyhow::Result<tempfile::NamedTempFile> {
    let response = ureq::get(url)
        .call()
        .map_err(|e| anyhow::anyhow!("HTTP fetch failed: {e}"))?;
    let mut tmp = tempfile::NamedTempFile::new()?;
    let mut reader = response.into_reader();
    std::io::copy(&mut reader, &mut tmp)?;
    Ok(tmp)
}
```

In `src/commands/audit.rs`, before loading the manifest:

```rust
let _tmp; // keep tempfile alive for lifetime of audit
let manifest_path: std::path::PathBuf = if manifest_loader::is_remote_url(&args.manifest_str) {
    _tmp = manifest_loader::fetch_remote_manifest(&args.manifest_str)?;
    _tmp.path().to_path_buf()
} else {
    std::path::PathBuf::from(&args.manifest_str)
};
```

**Step 4: Confirm GREEN**

```bash
cargo test --test manifest_loader_tests test_is_remote_ test_fetch_remote_
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing tests for remote manifest URL detection and fetch"
git commit -m "feat: support https:// manifest URLs in blazehash audit"
```

---

## Task 9: YARA scan during walk (`--yara`)

Feature-gated behind `yara` feature (uses `yara-x` crate — pure-Rust YARA reimplementation). Compile rules file at startup. During `hash_file`, after reading file bytes, run compiled rules against the buffer. Emit `[!] YARA:<rule_name> <path>` to stderr for each hit. Zero extra I/O — bytes already buffered for hashing.

**Files:**
- Create: `src/yara_scan.rs`
- Modify: `src/lib.rs` — `#[cfg(feature = "yara")] pub mod yara_scan`
- Modify: `src/hash.rs` — accept optional `YaraScanner` ref; run after buffering
- Modify: `src/cli.rs` — `#[cfg(feature = "yara")] #[arg(long)] yara: Option<PathBuf>`
- Test: `tests/yara_tests.rs`

**Step 1: Write failing tests (RED)**

Create `tests/yara_tests.rs`:

```rust
#[cfg(feature = "yara")]
mod yara_tests {
    use blazehash::yara_scan::YaraScanner;
    use tempfile::tempdir;

    const SIMPLE_RULE: &str = r#"
rule test_match {
    strings:
        $magic = "TESTMAGIC"
    condition:
        $magic
}"#;

    #[test]
    fn test_yara_scanner_compiles_rule() {
        let dir = tempdir().unwrap();
        let rules_file = dir.path().join("rules.yar");
        std::fs::write(&rules_file, SIMPLE_RULE).unwrap();
        assert!(YaraScanner::new(&rules_file).is_ok());
    }

    #[test]
    fn test_yara_scanner_matches_bytes() {
        let dir = tempdir().unwrap();
        let rules_file = dir.path().join("rules.yar");
        std::fs::write(&rules_file, SIMPLE_RULE).unwrap();
        let scanner = YaraScanner::new(&rules_file).unwrap();
        let hits = scanner.scan(b"prefix TESTMAGIC suffix").unwrap();
        assert!(!hits.is_empty(), "should match test_match rule");
        assert_eq!(hits[0], "test_match");
    }

    #[test]
    fn test_yara_scanner_no_match() {
        let dir = tempdir().unwrap();
        let rules_file = dir.path().join("rules.yar");
        std::fs::write(&rules_file, SIMPLE_RULE).unwrap();
        let scanner = YaraScanner::new(&rules_file).unwrap();
        let hits = scanner.scan(b"no magic bytes here").unwrap();
        assert!(hits.is_empty(), "should not match when pattern absent");
    }
}
```

**Step 2: Confirm RED**

```bash
cargo test --features yara --test yara_tests 2>&1 | grep -E "FAILED|error"
```

**Step 3: Implement (GREEN)**

Create `src/yara_scan.rs`:

```rust
#![cfg(feature = "yara")]

use anyhow::Result;
use std::path::Path;

pub struct YaraScanner {
    rules: yara_x::Rules,
}

impl YaraScanner {
    pub fn new(rules_file: &Path) -> Result<Self> {
        let source = std::fs::read_to_string(rules_file)?;
        let rules = yara_x::compile(&source)
            .map_err(|e| anyhow::anyhow!("YARA compile error: {e}"))?;
        Ok(Self { rules })
    }

    /// Returns names of all matching rules.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<String>> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner.scan(data)
            .map_err(|e| anyhow::anyhow!("YARA scan error: {e}"))?;
        Ok(results.matching_rules()
            .map(|r| r.identifier().to_string())
            .collect())
    }
}
```

Integrate into `hash_file` in `src/hash.rs`: after building the bytes buffer, if `yara_scanner.is_some()`, call `scanner.scan(&bytes)` and for each hit `eprintln!("[!] YARA:{rule} {path}")`.

**Step 4: Confirm GREEN**

```bash
cargo test --features yara --test yara_tests
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing tests for YARA rule scanning"
git commit -m "feat(yara): add --yara flag for YARA rule scanning during hash walk"
```

---

## Task 10: VirusTotal batch lookup (`blazehash vt`)

Query the VirusTotal v3 API with SHA-256 hashes from a manifest. API key from `VT_API_KEY` env var or `--api-key`. Rate-limit to 4 req/s (free tier). Annotate each record: `[clean]`, `[malicious N/M]`, `[unknown]`.

**Files:**
- Create: `src/commands/vt.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs` — `Vt` mode; `vt <manifest> [--api-key KEY]`
- Modify: `src/main.rs`
- Test: `tests/vt_tests.rs` — unit tests against mock HTTP server

**Step 1: Write failing tests (RED)**

Create `tests/vt_tests.rs`:

```rust
use blazehash::vt::{VtResult, classify_vt_response};

#[test]
fn test_classify_clean() {
    let json = serde_json::json!({
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "undetected": 70,
                    "harmless": 0,
                    "suspicious": 0
                }
            }
        }
    });
    let result = classify_vt_response(&json);
    assert_eq!(result, VtResult::Clean(70));
}

#[test]
fn test_classify_malicious() {
    let json = serde_json::json!({
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 35,
                    "undetected": 30,
                    "harmless": 0,
                    "suspicious": 0
                }
            }
        }
    });
    let result = classify_vt_response(&json);
    assert!(matches!(result, VtResult::Malicious { .. }));
    if let VtResult::Malicious { count, total } = result {
        assert_eq!(count, 35);
        assert_eq!(total, 65);
    }
}

#[test]
fn test_classify_unknown_on_404() {
    let json = serde_json::json!({});
    let result = classify_vt_response(&json);
    assert_eq!(result, VtResult::Unknown);
}
```

**Step 2: Confirm RED**

```bash
cargo test --test vt_tests 2>&1 | grep -E "FAILED|error"
```

**Step 3: Implement (GREEN)**

Create `src/vt.rs`:

```rust
use serde_json::Value;

#[derive(Debug, PartialEq)]
pub enum VtResult {
    Clean(u64),
    Malicious { count: u64, total: u64 },
    Unknown,
}

pub fn classify_vt_response(json: &Value) -> VtResult {
    let stats = json
        .pointer("/data/attributes/last_analysis_stats");
    match stats {
        None => VtResult::Unknown,
        Some(s) => {
            let malicious = s["malicious"].as_u64().unwrap_or(0);
            let undetected = s["undetected"].as_u64().unwrap_or(0);
            let suspicious = s["suspicious"].as_u64().unwrap_or(0);
            let total = malicious + undetected + suspicious + s["harmless"].as_u64().unwrap_or(0);
            if malicious > 0 {
                VtResult::Malicious { count: malicious, total }
            } else {
                VtResult::Clean(total)
            }
        }
    }
}
```

Create `src/commands/vt.rs` that loads the manifest, extracts sha256 hashes, calls `GET https://www.virustotal.com/api/v3/files/{hash}` with `x-apikey` header, parses response with `classify_vt_response`, and prints annotated output. Rate-limit with `std::thread::sleep(Duration::from_millis(250))` between requests.

Export `pub mod vt;` in `src/lib.rs`.

**Step 4: Confirm GREEN**

```bash
cargo test --test vt_tests
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing tests for VirusTotal response classification"
git commit -m "feat: add blazehash vt subcommand for VirusTotal batch hash lookup"
```

---

## Task 11: HTML chain-of-custody report (`blazehash report`)

Generate a standalone HTML file from a manifest. Includes: case metadata (examiner, case number, acquisition date), manifest table (path, size, hashes, entropy), signature verification status, and a SHA-256 fingerprint of the manifest itself.

Feature-gated behind `report` feature (uses `minijinja`). HTML only — PDF is out of scope (users can print-to-PDF from browser).

**Files:**
- Create: `src/commands/report.rs`
- Create: `src/report_template.html` (minijinja template embedded via `include_str!`)
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Test: `tests/report_tests.rs`

**Step 1: Write failing tests (RED)**

Create `tests/report_tests.rs`:

```rust
#[cfg(feature = "report")]
mod report_tests {
    use assert_cmd::Command;
    use tempfile::tempdir;
    use std::fs;

    #[test]
    fn test_report_generates_html_file() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("manifest.hash");
        let report = dir.path().join("report.html");
        fs::write(&manifest, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n").unwrap();

        Command::cargo_bin("blazehash")
            .unwrap()
            .args(["report", manifest.to_str().unwrap(),
                   "--examiner", "Jane Smith",
                   "--case", "Case-2026-001",
                   "-o", report.to_str().unwrap()])
            .assert()
            .success();

        assert!(report.exists(), "report.html should be created");
        let html = fs::read_to_string(&report).unwrap();
        assert!(html.contains("<html"), "output should be valid HTML");
        assert!(html.contains("Jane Smith"), "examiner name should appear");
        assert!(html.contains("Case-2026-001"), "case number should appear");
        assert!(html.contains("/f.bin"), "manifest entry should appear");
    }

    #[test]
    fn test_report_includes_manifest_hash() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("manifest.hash");
        let report = dir.path().join("report.html");
        fs::write(&manifest, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n").unwrap();

        Command::cargo_bin("blazehash")
            .unwrap()
            .args(["report", manifest.to_str().unwrap(),
                   "--examiner", "X", "--case", "Y",
                   "-o", report.to_str().unwrap()])
            .assert()
            .success();

        let html = fs::read_to_string(&report).unwrap();
        // SHA-256 of manifest file should be embedded
        assert!(html.contains("manifest-sha256") || html.contains("Manifest SHA-256"),
            "report must include manifest SHA-256 fingerprint");
    }
}
```

**Step 2: Confirm RED**

```bash
cargo test --features report --test report_tests 2>&1 | grep -E "FAILED|error"
```

**Step 3: Implement (GREEN)**

Create `src/report_template.html` (minijinja template):

```html
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Chain of Custody Report — {{ case }}</title>
<style>
body { font-family: monospace; margin: 2em; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; }
th { background: #eee; }
.meta { margin-bottom: 1.5em; }
</style>
</head>
<body>
<h1>Chain of Custody Report</h1>
<div class="meta">
  <p><strong>Case:</strong> {{ case }}</p>
  <p><strong>Examiner:</strong> {{ examiner }}</p>
  <p><strong>Generated:</strong> {{ generated }}</p>
  <p><strong>Manifest SHA-256:</strong> <code class="manifest-sha256">{{ manifest_sha256 }}</code></p>
  {% if sig_status %}<p><strong>Signature:</strong> {{ sig_status }}</p>{% endif %}
</div>
<table>
<tr><th>Path</th><th>Size</th>{% for algo in algos %}<th>{{ algo }}</th>{% endfor %}</tr>
{% for row in rows %}
<tr><td>{{ row.path }}</td><td>{{ row.size }}</td>{% for h in row.hashes %}<td>{{ h }}</td>{% endfor %}</tr>
{% endfor %}
</table>
</body></html>
```

Create `src/commands/report.rs` that: loads manifest, computes SHA-256 of manifest file, renders template via `minijinja::Environment`, writes output.

**Step 4: Confirm GREEN**

```bash
cargo test --features report --test report_tests
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing tests for HTML chain-of-custody report"
git commit -m "feat(report): add blazehash report subcommand generating HTML chain-of-custody"
```

---

## Task 12: Docker layer hashing (`blazehash image`)

Feature-gated behind `docker` feature. Pull an OCI image manifest from a registry (Docker Hub or any OCI-compliant registry), then hash each layer blob (compressed tar.gz) using the configured algorithms. Output as a manifest with layer digest as the path.

**Files:**
- Create: `src/commands/image.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Test: `tests/image_tests.rs` — unit tests for layer hash parsing; integration test pulls a tiny image (uses `busybox:musl` from Docker Hub, skip in CI by default)

**Step 1: Write failing tests (RED)**

Create `tests/image_tests.rs`:

```rust
#[cfg(feature = "docker")]
mod image_tests {
    use blazehash::image::parse_image_ref;

    #[test]
    fn test_parse_image_ref_with_tag() {
        let r = parse_image_ref("nginx:latest").unwrap();
        assert_eq!(r.name, "library/nginx");
        assert_eq!(r.tag, "latest");
        assert_eq!(r.registry, "index.docker.io");
    }

    #[test]
    fn test_parse_image_ref_with_digest() {
        let r = parse_image_ref("alpine@sha256:abc123").unwrap();
        assert_eq!(r.name, "library/alpine");
        assert_eq!(r.digest, Some("sha256:abc123".to_string()));
    }

    #[test]
    fn test_parse_image_ref_custom_registry() {
        let r = parse_image_ref("ghcr.io/org/repo:v1.0").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.name, "org/repo");
        assert_eq!(r.tag, "v1.0");
    }

    #[test]
    fn test_parse_image_ref_implicit_latest() {
        let r = parse_image_ref("ubuntu").unwrap();
        assert_eq!(r.tag, "latest");
    }
}
```

**Step 2: Confirm RED**

```bash
cargo test --features docker --test image_tests 2>&1 | grep -E "FAILED|error"
```

**Step 3: Implement (GREEN)**

Create `src/image.rs`:

```rust
#![cfg(feature = "docker")]

use anyhow::{bail, Result};

#[derive(Debug)]
pub struct ImageRef {
    pub registry: String,
    pub name: String,
    pub tag: String,
    pub digest: Option<String>,
}

/// Parse "registry/name:tag" or "name:tag" or "name@digest" references.
pub fn parse_image_ref(s: &str) -> Result<ImageRef> {
    // Detect registry: contains a dot or colon before the first slash
    let (registry, rest) = if let Some(slash) = s.find('/') {
        let prefix = &s[..slash];
        if prefix.contains('.') || prefix.contains(':') {
            (prefix.to_string(), s[slash + 1..].to_string())
        } else {
            ("index.docker.io".to_string(), s.to_string())
        }
    } else {
        ("index.docker.io".to_string(), s.to_string())
    };

    let (name_part, digest) = if let Some(at) = rest.find('@') {
        (rest[..at].to_string(), Some(rest[at + 1..].to_string()))
    } else {
        (rest.clone(), None)
    };

    let (bare_name, tag) = if let Some(colon) = name_part.rfind(':') {
        (name_part[..colon].to_string(), name_part[colon + 1..].to_string())
    } else {
        (name_part.clone(), "latest".to_string())
    };

    // Docker Hub implicit library/ prefix
    let name = if registry == "index.docker.io" && !bare_name.contains('/') {
        format!("library/{bare_name}")
    } else {
        bare_name
    };

    Ok(ImageRef { registry, name, tag, digest })
}
```

Create `src/commands/image.rs` using `oci-distribution` to: authenticate anonymously, fetch the image manifest, iterate layers, stream each layer through the hash algorithms, output results as a blazehash manifest. Layers are identified by their OCI digest (e.g. `sha256:abc...`).

**Step 4: Confirm GREEN**

```bash
cargo test --features docker --test image_tests
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing tests for Docker/OCI image reference parsing"
git commit -m "feat(docker): add blazehash image subcommand for OCI layer hashing"
```

---

## Task 13: Parquet output (`--format parquet`)

Feature-gated behind `parquet` feature. Write results to Apache Parquet format using the `arrow` + `parquet` crates. Schema: `path STRING, size INT64, entropy DOUBLE, <algo> STRING, ...`. One row per file. Useful for large-scale DFIR pipelines (DuckDB, Spark, pandas).

**Files:**
- Create: `src/format/parquet_fmt.rs`
- Modify: `src/format/mod.rs`
- Modify: `src/cli.rs` — `Parquet` variant in `OutputFormat`
- Test: `tests/format_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/format_tests.rs` (behind `#[cfg(feature = "parquet")]`):

```rust
#[cfg(feature = "parquet")]
#[test]
fn parquet_output_creates_file() {
    use blazehash::format::write_parquet;
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.parquet");

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abc".to_string());
    let result = FileHashResult { path: PathBuf::from("/f.bin"), size: 5, hashes, entropy: None };

    write_parquet(&out, &[result], &[Algorithm::Blake3]).unwrap();
    assert!(out.exists(), "parquet file should be created");
    assert!(out.metadata().unwrap().len() > 0, "parquet file should not be empty");
}
```

**Step 2: Confirm RED**

```bash
cargo test --features parquet parquet_output_creates_file 2>&1 | grep -E "FAILED|error"
```

**Step 3: Implement (GREEN)**

Create `src/format/parquet_fmt.rs`:

```rust
#![cfg(feature = "parquet")]

use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use arrow::array::{Float64Array, Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::arrow_writer::ArrowWriter;
use std::path::Path;
use std::sync::Arc;

pub fn write_parquet(path: &Path, results: &[FileHashResult], algos: &[Algorithm]) -> Result<()> {
    let mut fields = vec![
        Field::new("path", DataType::Utf8, false),
        Field::new("size", DataType::Int64, false),
        Field::new("entropy", DataType::Float64, true),
    ];
    for algo in algos {
        fields.push(Field::new(algo.name(), DataType::Utf8, true));
    }
    let schema = Arc::new(Schema::new(fields));

    let paths: StringArray = results.iter().map(|r| Some(r.path.to_string_lossy().into_owned())).collect();
    let sizes: Int64Array = results.iter().map(|r| Some(r.size as i64)).collect();
    let entropies: Float64Array = results.iter().map(|r| r.entropy).collect();

    let mut columns: Vec<Arc<dyn arrow::array::Array>> = vec![
        Arc::new(paths),
        Arc::new(sizes),
        Arc::new(entropies),
    ];
    for algo in algos {
        let col: StringArray = results.iter().map(|r| r.hashes.get(algo).cloned()).collect();
        columns.push(Arc::new(col));
    }

    let batch = RecordBatch::try_new(schema.clone(), columns)?;
    let file = std::fs::File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema, None)?;
    writer.write(&batch)?;
    writer.close()?;
    Ok(())
}
```

Export in `src/format/mod.rs`:

```rust
#[cfg(feature = "parquet")]
pub mod parquet_fmt;
#[cfg(feature = "parquet")]
pub use parquet_fmt::write_parquet;
```

**Step 4: Confirm GREEN**

```bash
cargo test --features parquet parquet_output_creates_file
```

**Step 5: Commits**

```bash
git commit -m "test(RED): add failing test for --format parquet output"
git commit -m "feat(parquet): add --format parquet Apache Parquet output"
```

---

## Task 14: CI — add new features to matrix

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Add feature flag variants to cargo test matrix**

In the `test` job, change:
```yaml
- run: cargo test --all-features
```
to also run feature-specific tests:
```yaml
- run: cargo test --all-features
- run: cargo test --features nsrl
- run: cargo test --features yara
- run: cargo test --features report
- run: cargo test --features docker
- run: cargo test --features parquet
```

Note: `yara`, `docker`, and `parquet` features require additional system dependencies. Add install steps for each as needed:
- `yara-x` is pure Rust — no system dep
- `oci-distribution` — pure Rust
- `parquet`/`arrow` — pure Rust

**Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: test nsrl, yara, report, docker, parquet feature flag variants"
```

---

## Task 15: README + docs update

**Files:**
- Modify: `README.md` — add `merge`, `update`, `watch`, `vt`, `report`, `image` subcommands; `--entropy`, `--yara`, `--format sqlite/parquet` flags
- Modify: `docs/` — add pages for new subcommands if mkdocs site exists

**Step 1: Update README quick-start table**

Add new subcommands to the command reference table in README.md.

**Step 2: Commit**

```bash
git add README.md docs/
git commit -m "docs: document feature batch 2 subcommands and flags"
```
