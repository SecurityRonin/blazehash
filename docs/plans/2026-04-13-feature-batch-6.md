# Feature Batch 6 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Five manifest-intelligence and utility features: manifest statistics, entry filtering, path normalization, binary selfcheck, and archive hashing (tar/zip/gzip).

**Architecture:**
- `stats` and `filter` and `normalize` are pure manifest transformations — no new deps
- `selfcheck` hashes `std::env::current_exe()` — no new deps
- `archive` adds a `zip` optional dep (tar/flate2 already available via docker feature); gated behind `archive` feature flag
- All wired through existing `cli.rs` / `main.rs` pattern

**Tech Stack:** Rust, existing `manifest_loader.rs`, `merkle.rs`, optional `zip` crate, `std::env::current_exe()`

---

### Task 1: `blazehash stats` — manifest statistics

**Files:**
- Create: `src/commands/stats.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Create: `tests/stats_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/stats_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/contract.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  images/photo.jpg\n",
        "blake3  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  docs/notes.txt\n",
        "sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  README.md\n",
    )).unwrap();
    p
}

#[test]
fn test_stats_total_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stats", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should report 4 entries
    assert!(stdout.contains("4"), "expected 4 in output, got:\n{stdout}");
}

#[test]
fn test_stats_algorithm_breakdown() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stats", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sha256") || stdout.contains("SHA-256"), "expected sha256 breakdown");
    assert!(stdout.contains("blake3") || stdout.contains("BLAKE3"), "expected blake3 breakdown");
}

#[test]
fn test_stats_extension_breakdown() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stats", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Has .pdf, .jpg, .txt, .md
    assert!(stdout.contains(".pdf") || stdout.contains("pdf"), "expected .pdf in output");
}

#[test]
fn test_stats_json_output() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stats", manifest.to_str().unwrap(), "--json"])
        .output().unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("output should be valid JSON");
    assert!(json["total_entries"].as_u64().unwrap_or(0) > 0);
    assert!(json["algorithms"].is_object() || json["algorithms"].is_array());
}

#[test]
fn test_stats_missing_manifest_fails() {
    Command::cargo_bin("blazehash").unwrap()
        .args(["stats", "/nonexistent/file.hash"])
        .assert().failure();
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test stats_tests 2>&1 | grep -E "error|FAILED|test result"
```

Expected: subcommand not found / compile error.

**Step 3: Implement `src/commands/stats.rs`**

```rust
//! Manifest statistics: entry count, algorithm breakdown, extension breakdown.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ManifestStats {
    pub total_entries: usize,
    /// Count per algorithm (e.g. {"sha256": 3, "blake3": 1})
    pub algorithms: HashMap<String, usize>,
    /// Count per file extension (e.g. {".pdf": 2, ".jpg": 1})
    pub extensions: HashMap<String, usize>,
    /// Unique paths count (should equal total_entries unless duplicates)
    pub unique_paths: usize,
}

pub fn compute_stats(manifest_path: &Path) -> Result<ManifestStats> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut stats = ManifestStats::default();
    let mut paths: std::collections::HashSet<String> = Default::default();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            stats.total_entries += 1;
            let algo = parts[0].trim().to_lowercase();
            *stats.algorithms.entry(algo).or_insert(0) += 1;

            let path = parts[2].trim();
            paths.insert(path.to_string());

            // Extension
            let ext = std::path::Path::new(path)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"))
                .unwrap_or_else(|| "(none)".to_string());
            *stats.extensions.entry(ext).or_insert(0) += 1;
        }
    }

    stats.unique_paths = paths.len();
    Ok(stats)
}

pub fn print_stats(stats: &ManifestStats) {
    println!("Entries:  {}", stats.total_entries);
    println!("Unique:   {}", stats.unique_paths);
    println!();
    println!("Algorithms:");
    let mut algos: Vec<_> = stats.algorithms.iter().collect();
    algos.sort_by_key(|(k, _)| k.as_str());
    for (algo, count) in algos {
        println!("  {algo:<12} {count}");
    }
    println!();
    println!("Extensions:");
    let mut exts: Vec<_> = stats.extensions.iter().collect();
    exts.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (ext, count) in exts.iter().take(20) {
        println!("  {ext:<12} {count}");
    }
}
```

**Step 4: Wire into CLI**

Add `Stats` to `Mode` in `src/cli.rs`, add `--json` flag.

Dispatch in `src/main.rs`:
```rust
Mode::Stats => {
    let stats = crate::commands::stats::compute_stats(&manifest_path)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        crate::commands::stats::print_stats(&stats);
    }
}
```

**Step 5: Run tests, commit GREEN**

```bash
cargo test --all-features --test stats_tests 2>&1 | grep -E "FAILED|ok|test result"
git add src/commands/stats.rs src/commands/mod.rs src/cli.rs src/main.rs tests/stats_tests.rs
git commit -m "feat: blazehash stats — manifest statistics (entry count, algorithm + extension breakdown)"
```

---

### Task 2: `blazehash filter` — filter manifest entries

**Files:**
- Create: `src/commands/filter.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Create: `tests/filter_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/filter_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/contract.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  images/photo.jpg\n",
        "blake3  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  docs/notes.txt\n",
        "sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  README.md\n",
    )).unwrap();
    p
}

#[test]
fn test_filter_by_path_glob() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("filtered.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["filter", manifest.to_str().unwrap(),
               "--include", "docs/**",
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("contract.pdf"), "expected docs/contract.pdf");
    assert!(content.contains("notes.txt"), "expected docs/notes.txt");
    assert!(!content.contains("photo.jpg"), "images/ should be excluded");
    assert!(!content.contains("README.md"), "README.md should be excluded");
}

#[test]
fn test_filter_by_algorithm() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("filtered.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["filter", manifest.to_str().unwrap(),
               "--algo", "blake3",
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("blake3"), "should keep blake3 entries");
    assert!(!content.contains("sha256"), "should not keep sha256 entries");
}

#[test]
fn test_filter_stdout_when_no_output() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["filter", manifest.to_str().unwrap(), "--include", "*.md"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("README.md"), "README.md should pass *.md filter");
    assert!(!stdout.contains("contract.pdf"), "PDF should be excluded");
}

#[test]
fn test_filter_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["filter", manifest.to_str().unwrap(), "--include", "docs/**"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## case: CASE-001"), "headers must be preserved");
}

#[test]
fn test_filter_no_match_outputs_only_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["filter", manifest.to_str().unwrap(), "--include", "nonexistent/**"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // No hash entries, only headers (or empty)
    assert!(!stdout.contains("sha256") && !stdout.contains("blake3"),
        "no hash lines when no match, got:\n{stdout}");
}
```

**Step 2: Confirm RED**

**Step 3: Implement `src/commands/filter.rs`**

```rust
//! Filter manifest entries by path glob, algorithm, or extension.

use anyhow::Result;
use std::io::Write;
use std::path::Path;

/// Filter criteria — all are AND'd together.
pub struct FilterOpts<'a> {
    /// Glob pattern(s) to include (fnmatch against the path in each entry).
    pub include: Option<&'a [String]>,
    /// Only keep entries for this algorithm (case-insensitive).
    pub algo: Option<&'a str>,
}

pub fn filter_manifest<W: Write>(
    manifest_path: &Path,
    opts: &FilterOpts<'_>,
    out: &mut W,
) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;

    for line in content.lines() {
        let trimmed = line.trim();

        // Always pass through headers and blank lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue; // skip malformed lines
        }

        let algo = parts[0].trim();
        let path = parts[2].trim();

        // Algorithm filter
        if let Some(required_algo) = opts.algo {
            if !algo.eq_ignore_ascii_case(required_algo) {
                continue;
            }
        }

        // Glob include filter
        if let Some(patterns) = opts.include {
            let matched = patterns.iter().any(|pat| {
                glob_match(pat, path)
            });
            if !matched {
                continue;
            }
        }

        writeln!(out, "{line}")?;
    }

    Ok(())
}

/// Simple glob matching: `**` matches any path segment(s), `*` matches within a segment.
fn glob_match(pattern: &str, path: &str) -> bool {
    // Normalize separators
    let path = path.replace('\\', "/");
    let pattern = pattern.replace('\\', "/");
    glob_match_inner(&pattern, &path)
}

fn glob_match_inner(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern == "**" {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix("**/") {
        // Match zero or more path segments
        if glob_match_inner(rest, text) {
            return true;
        }
        // Try consuming one segment from text
        if let Some(slash) = text.find('/') {
            return glob_match_inner(pattern, &text[slash + 1..]);
        }
        return false;
    }
    // Match one path segment or simple wildcard
    let (pat_seg, pat_rest) = match pattern.find('/') {
        Some(i) => (&pattern[..i], Some(&pattern[i + 1..])),
        None => (pattern, None),
    };
    let (txt_seg, txt_rest) = match text.find('/') {
        Some(i) => (&text[..i], Some(&text[i + 1..])),
        None => (text, None),
    };

    if !segment_match(pat_seg, txt_seg) {
        return false;
    }
    match (pat_rest, txt_rest) {
        (None, None) => true,
        (Some(p), Some(t)) => glob_match_inner(p, t),
        (None, Some(_)) => false,
        (Some(_), None) => false,
    }
}

fn segment_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }
    // Simple wildcard matching for single segment
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            return text[pos..].ends_with(part);
        } else if let Some(found) = text[pos..].find(part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }
    true
}
```

**Step 4: Wire into CLI**

Add `Filter` to `Mode`. Add `--include` (multiple) and `--algo` flags.

```rust
Mode::Filter => {
    let includes: Option<Vec<String>> = cli.include.clone();
    let includes_ref: Option<&[String]> = includes.as_deref();
    let opts = crate::commands::filter::FilterOpts {
        include: includes_ref,
        algo: cli.filter_algo.as_deref(),
    };
    if let Some(out_path) = &cli.output {
        let mut f = std::fs::File::create(out_path)?;
        crate::commands::filter::filter_manifest(&manifest_path, &opts, &mut f)?;
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        crate::commands::filter::filter_manifest(&manifest_path, &opts, &mut handle)?;
    }
}
```

**Step 5: Run tests, commit GREEN**

---

### Task 3: `blazehash normalize` — path normalization in manifests

**Files:**
- Create: `src/commands/normalize.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Create: `tests/normalize_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/normalize_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  /mnt/evidence/docs/contract.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  /mnt/evidence/images/photo.jpg\n",
    )).unwrap();
    p
}

#[test]
fn test_normalize_strip_prefix() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["normalize", manifest.to_str().unwrap(),
               "--strip-prefix", "/mnt/evidence/"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("docs/contract.pdf"), "should strip prefix");
    assert!(!stdout.contains("/mnt/evidence/"), "prefix must be removed");
}

#[test]
fn test_normalize_add_prefix() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["normalize", manifest.to_str().unwrap(),
               "--add-prefix", "C:\\Evidence\\"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("C:\\Evidence\\") || stdout.contains("C:/Evidence/"),
        "should add prefix");
}

#[test]
fn test_normalize_strip_and_add_prefix() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["normalize", manifest.to_str().unwrap(),
               "--strip-prefix", "/mnt/evidence/",
               "--add-prefix", "/case/001/"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("/case/001/docs/contract.pdf"), "strip+add should rebase paths");
}

#[test]
fn test_normalize_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["normalize", manifest.to_str().unwrap(),
               "--strip-prefix", "/mnt/"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## case: CASE-001"), "headers must be preserved");
}

#[test]
fn test_normalize_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("normalized.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["normalize", manifest.to_str().unwrap(),
               "--strip-prefix", "/mnt/evidence/",
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("docs/contract.pdf"));
    assert!(!content.contains("/mnt/evidence/"));
}
```

**Step 2: Confirm RED**

**Step 3: Implement `src/commands/normalize.rs`**

```rust
//! Normalize file paths in a manifest (strip/add prefix, forward/backward slash conversion).

use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub struct NormalizeOpts<'a> {
    pub strip_prefix: Option<&'a str>,
    pub add_prefix: Option<&'a str>,
}

pub fn normalize_manifest<W: Write>(
    manifest_path: &Path,
    opts: &NormalizeOpts<'_>,
    out: &mut W,
) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            writeln!(out, "{line}")?;
            continue;
        }

        let algo = parts[0];
        let hash = parts[1];
        let mut path = parts[2].trim().to_string();

        // Strip prefix
        if let Some(prefix) = opts.strip_prefix {
            if path.starts_with(prefix) {
                path = path[prefix.len()..].to_string();
            }
        }

        // Add prefix
        if let Some(prefix) = opts.add_prefix {
            path = format!("{prefix}{path}");
        }

        writeln!(out, "{algo}  {hash}  {path}")?;
    }

    Ok(())
}
```

**Step 4: Wire into CLI**

Add `Normalize` mode, `--strip-prefix` and `--add-prefix` flags.

**Step 5: Run tests, commit GREEN**

---

### Task 4: `blazehash selfcheck` — binary integrity verification

**Files:**
- Create: `src/commands/selfcheck.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Create: `tests/selfcheck_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/selfcheck_tests.rs
use assert_cmd::Command;

#[test]
fn test_selfcheck_prints_hash() {
    let out = Command::cargo_bin("blazehash").unwrap()
        .arg("selfcheck")
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should print a BLAKE3 hash (64 hex chars) of the binary
    let has_blake3_hash = stdout.split_whitespace()
        .any(|tok| tok.len() == 64 && tok.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(has_blake3_hash, "expected 64-char hex hash in output, got:\n{stdout}");
}

#[test]
fn test_selfcheck_json_output() {
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["selfcheck", "--json"])
        .output().unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("selfcheck --json must produce valid JSON");
    assert!(json["blake3"].as_str().map(|h| h.len() == 64).unwrap_or(false),
        "JSON should have blake3 field with 64-char hash");
    assert!(json["path"].is_string(), "JSON should include binary path");
}

#[test]
fn test_selfcheck_includes_size() {
    let out = Command::cargo_bin("blazehash").unwrap()
        .arg("selfcheck")
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Output should mention a size
    assert!(stdout.contains("size") || stdout.contains("bytes") || stdout.contains("MB"),
        "selfcheck should report binary size, got:\n{stdout}");
}

#[test]
fn test_selfcheck_deterministic() {
    // Two consecutive runs must produce the same hash
    let out1 = Command::cargo_bin("blazehash").unwrap()
        .args(["selfcheck", "--json"]).output().unwrap();
    let out2 = Command::cargo_bin("blazehash").unwrap()
        .args(["selfcheck", "--json"]).output().unwrap();
    assert_eq!(out1.stdout, out2.stdout, "selfcheck must be deterministic");
}
```

**Step 2: Confirm RED**

**Step 3: Implement `src/commands/selfcheck.rs`**

```rust
//! Binary self-integrity check: hash the blazehash executable itself.
//!
//! Useful to detect tampering of the forensic tool before use.
//! Prints BLAKE3 + SHA-256 of the current binary and its size.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct SelfCheckResult {
    pub path: PathBuf,
    pub size: u64,
    pub blake3: String,
    pub sha256: String,
}

pub fn selfcheck() -> Result<SelfCheckResult> {
    let exe = std::env::current_exe()?;
    let bytes = std::fs::read(&exe)?;
    let size = bytes.len() as u64;

    // BLAKE3
    let blake3 = {
        let mut h = blake3::Hasher::new();
        h.update(&bytes);
        h.finalize().to_hex().to_string()
    };

    // SHA-256
    let sha256 = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    };

    Ok(SelfCheckResult { path: exe, size, blake3, sha256 })
}

pub fn print_selfcheck(r: &SelfCheckResult) {
    println!("Binary:   {}", r.path.display());
    let mb = r.size as f64 / 1_048_576.0;
    println!("Size:     {} bytes ({:.2} MB)", r.size, mb);
    println!("BLAKE3:   {}", r.blake3);
    println!("SHA-256:  {}", r.sha256);
}
```

**Step 4: Wire into CLI**

Add `Selfcheck` mode.

```rust
Mode::Selfcheck => {
    let result = crate::commands::selfcheck::selfcheck()?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        crate::commands::selfcheck::print_selfcheck(&result);
    }
}
```

**Step 5: Run tests, commit GREEN**

---

### Task 5: `blazehash archive` — hash contents of tar/zip archives

**Files:**
- Create: `src/commands/archive.rs`
- Modify: `src/commands/mod.rs`, `Cargo.toml` (add `zip` optional dep, `archive` feature)
- Modify: `src/cli.rs`, `src/main.rs`
- Create: `tests/archive_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/archive_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;
use std::io::Write;

fn create_zip(dir: &TempDir) -> std::path::PathBuf {
    let zip_path = dir.path().join("evidence.zip");
    let file = fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::<()>::default()
        .compression_method(zip::CompressionMethod::Stored);
    zip.start_file("docs/contract.pdf", options).unwrap();
    zip.write_all(b"fake pdf content").unwrap();
    zip.start_file("images/photo.jpg", options).unwrap();
    zip.write_all(b"fake jpg content").unwrap();
    zip.finish().unwrap();
    zip_path
}

#[test]
fn test_archive_zip_lists_entries() {
    let dir = TempDir::new().unwrap();
    let zip_path = create_zip(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["archive", zip_path.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success(), "archive command failed: {}",
        String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("contract.pdf"), "expected contract.pdf in output");
    assert!(stdout.contains("photo.jpg"), "expected photo.jpg in output");
}

#[test]
fn test_archive_zip_produces_hashes() {
    let dir = TempDir::new().unwrap();
    let zip_path = create_zip(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["archive", zip_path.to_str().unwrap()])
        .output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Each entry line should contain a 64-char blake3 hash
    let has_hash = stdout.lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('%') && !l.is_empty())
        .any(|l| l.split_whitespace().any(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())));
    assert!(has_hash, "expected blake3 hashes in archive output:\n{stdout}");
}

#[test]
fn test_archive_zip_deterministic() {
    let dir = TempDir::new().unwrap();
    let zip_path = create_zip(&dir);
    let out1 = Command::cargo_bin("blazehash").unwrap()
        .args(["archive", zip_path.to_str().unwrap()])
        .output().unwrap().stdout;
    let out2 = Command::cargo_bin("blazehash").unwrap()
        .args(["archive", zip_path.to_str().unwrap()])
        .output().unwrap().stdout;
    assert_eq!(out1, out2, "archive output must be deterministic");
}

#[test]
fn test_archive_unsupported_format_fails() {
    Command::cargo_bin("blazehash").unwrap()
        .args(["archive", "/tmp/notanarchive.xyz"])
        .assert().failure();
}

#[test]
fn test_archive_output_to_file() {
    let dir = TempDir::new().unwrap();
    let zip_path = create_zip(&dir);
    let out_path = dir.path().join("archive.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["archive", zip_path.to_str().unwrap(),
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("contract.pdf"));
}
```

**Step 2: Add dep + feature**

In `Cargo.toml`:
```toml
[features]
archive = ["dep:zip"]

[dependencies]
zip = { version = "2", optional = true }
```

**Step 3: Implement `src/commands/archive.rs`**

```rust
//! Hash file contents inside tar (.tar, .tar.gz, .tgz) and zip archives.
//!
//! Produces a blazehash manifest of all archive members without extracting to disk.

use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

fn ext2(path: &Path) -> (&str, &str) {
    let s = path.to_str().unwrap_or("");
    if s.ends_with(".tar.gz") || s.ends_with(".tgz") {
        (".tar.gz", "tar+gzip")
    } else if s.ends_with(".tar") {
        (".tar", "tar")
    } else if s.ends_with(".zip") {
        (".zip", "zip")
    } else {
        ("", "unknown")
    }
}

pub fn hash_archive<W: Write>(archive_path: &Path, out: &mut W) -> Result<()> {
    let (_, kind) = ext2(archive_path);
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

fn hash_tar<W: Write>(path: &Path, gzip: bool, out: &mut W) -> Result<()> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    if gzip {
        let decoder = flate2::read::GzDecoder::new(file);
        hash_tar_reader(decoder, out)
    } else {
        hash_tar_reader(file, out)
    }
}

fn hash_tar_reader<R: std::io::Read, W: Write>(reader: R, out: &mut W) -> Result<()> {
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
```

**Step 4: Wire into CLI**

Add `Archive` mode. Dispatch:
```rust
Mode::Archive => {
    let archive_path = cli.target.as_ref()
        .ok_or_else(|| anyhow::anyhow!("archive path required"))?;
    if let Some(out_path) = &cli.output {
        let mut f = std::fs::File::create(out_path)?;
        crate::commands::archive::hash_archive(archive_path.as_ref(), &mut f)?;
    } else {
        let stdout = std::io::stdout();
        crate::commands::archive::hash_archive(archive_path.as_ref(), &mut stdout.lock())?;
    }
}
```

**Step 5: Run tests, commit GREEN**

Note: tests run with `--all-features` to include the `archive` feature.

---

### Task 6: Final integration check

**Step 1: Full test suite**

```bash
cargo test --all-features 2>&1 | tail -30
```

**Step 2: Clippy**

```bash
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -20
```

**Step 3: Docs and commit**

Mark plan complete. Push.

---

## Summary

| Task | Feature | Key file |
|------|---------|----------|
| 1 | `blazehash stats` — manifest statistics | `src/commands/stats.rs` |
| 2 | `blazehash filter` — filter entries by glob/algo | `src/commands/filter.rs` |
| 3 | `blazehash normalize` — strip/add path prefix | `src/commands/normalize.rs` |
| 4 | `blazehash selfcheck` — hash binary itself | `src/commands/selfcheck.rs` |
| 5 | `blazehash archive` — hash tar/zip contents | `src/commands/archive.rs` |
| 6 | Integration check + push | — |
