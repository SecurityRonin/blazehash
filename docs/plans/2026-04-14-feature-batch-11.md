# blazehash Feature Batch 11 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Five manifest transformation utilities — pivot, rename, slice, stamp, grep.

**Architecture:** Same Mode dispatch pattern. Two commits per task: RED then GREEN. `cargo clippy --all-features -- -D warnings` must produce zero errors before the GREEN commit.

**Tech Stack:** Rust std + `regex` crate (already in tree via yara-x transitive dep — verify before use; if absent add it).

---

### Task 1: `blazehash pivot` — extract one algorithm column as sumfile

**Files:** Create `tests/pivot_tests.rs`, `src/commands/pivot.rs`. Modify `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`.

**What it does:** A manifest may contain multiple algorithms per file. `pivot` extracts just one algorithm's entries and emits them in standard `<hash>  <path>` (sha256sum/md5sum compatible) format. Useful when feeding hashes to third-party tools.

Usage: `blazehash pivot --pivot-algo sha256 manifest.hash > sha256sums.txt`

**New CLI field:** `pivot_algo: Option<String>` → `#[arg(long = "pivot-algo")]`

**Tests:**
```rust
// tests/pivot_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_multi_algo_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("multi.hash");
    fs::write(&p, concat!(
        "blake3  bbbbbbbb  file1.txt\n",
        "sha256  aaaaaaaa  file1.txt\n",
        "blake3  cccccccc  file2.txt\n",
        "sha256  dddddddd  file2.txt\n",
    )).unwrap();
    p
}

#[test]
fn test_pivot_extracts_single_algo() {
    let dir = TempDir::new().unwrap();
    let m = make_multi_algo_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["pivot", m.to_str().unwrap(), "--pivot-algo", "sha256"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let lines: Vec<_> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "should have 2 sha256 entries");
    assert!(lines.iter().all(|l| !l.contains("blake3")), "no blake3 lines");
}

#[test]
fn test_pivot_output_format_is_sumfile() {
    let dir = TempDir::new().unwrap();
    let m = make_multi_algo_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["pivot", m.to_str().unwrap(), "--pivot-algo", "sha256"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        // sumfile format: "<hash>  <path>" (no algo prefix)
        assert!(!line.starts_with("sha256"), "algo prefix should be stripped");
        assert!(line.contains("  "), "should have two-space delimiter");
    }
}

#[test]
fn test_pivot_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "## case-id: X\nblake3  aaaa  f.txt\nsha256  bbbb  f.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["pivot", p.to_str().unwrap(), "--pivot-algo", "sha256"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## case-id: X"));
}

#[test]
fn test_pivot_output_to_file() {
    let dir = TempDir::new().unwrap();
    let m = make_multi_algo_manifest(&dir);
    let out_file = dir.path().join("sha256sums.txt");
    Command::cargo_bin("blazehash").unwrap()
        .args(["pivot", m.to_str().unwrap(), "--pivot-algo", "sha256",
               "-o", out_file.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("file1.txt") && content.contains("file2.txt"));
}

#[test]
fn test_pivot_missing_algo_flag_fails() {
    let dir = TempDir::new().unwrap();
    let m = make_multi_algo_manifest(&dir);
    Command::cargo_bin("blazehash").unwrap()
        .args(["pivot", m.to_str().unwrap()])
        .assert().failure();
}
```

**Implementation:**
```rust
// src/commands/pivot.rs
use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn pivot_manifest(manifest_path: &Path, algo: &str, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let algo_lower = algo.to_lowercase();

    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() { continue; }
        if t.starts_with('#') || t.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        let parts: Vec<&str> = t.splitn(3, "  ").collect();
        if parts.len() == 3 && parts[0].trim().to_lowercase() == algo_lower {
            let hash = parts[1].trim();
            let path = parts[2].trim();
            writeln!(out, "{hash}  {path}")?;
        }
    }
    Ok(())
}
```

Dispatch:
```rust
if let Mode::Pivot = cli.mode() {
    let manifest_path = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("pivot: missing manifest path"))?;
    let algo = cli.pivot_algo.as_deref()
        .ok_or_else(|| anyhow::anyhow!("pivot: --pivot-algo is required"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    commands::pivot::pivot_manifest(manifest_path, algo, &mut out)?;
    return Ok(());
}
```

**Commits:**
```bash
git add tests/pivot_tests.rs
git commit -m "test(RED): add failing tests for blazehash pivot"

git add src/commands/pivot.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash pivot — extract single-algorithm column as sumfile"
```

---

### Task 2: `blazehash rename` — path find-and-replace in manifest

**Files:** Create `tests/rename_tests.rs`, `src/commands/rename.rs`. Modify the usual 3.

**What it does:** Replaces occurrences of `--rename-from <old>` with `--rename-to <new>` in every path field of the manifest. Simple string replacement (not regex). Headers preserved.

**New CLI fields:**
- `rename_from: Option<String>` → `#[arg(long = "rename-from")]`
- `rename_to: Option<String>` → `#[arg(long = "rename-to", default_value = "")]`

**Tests:**
```rust
// tests/rename_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("m.hash");
    fs::write(&p, concat!(
        "## case-id: X\n",
        "blake3  aaaa  /old/prefix/file1.txt\n",
        "blake3  bbbb  /old/prefix/file2.txt\n",
        "blake3  cccc  /other/file3.txt\n",
    )).unwrap();
    p
}

#[test]
fn test_rename_replaces_path_prefix() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["rename", m.to_str().unwrap(),
               "--rename-from", "/old/prefix",
               "--rename-to", "/new/prefix"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("/new/prefix/file1.txt"));
    assert!(s.contains("/new/prefix/file2.txt"));
    assert!(!s.contains("/old/prefix"), "old prefix should be gone");
}

#[test]
fn test_rename_only_affects_matching_paths() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["rename", m.to_str().unwrap(),
               "--rename-from", "/old/prefix",
               "--rename-to", "/new"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("/other/file3.txt"), "unmatched path should be unchanged");
}

#[test]
fn test_rename_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["rename", m.to_str().unwrap(),
               "--rename-from", "/old", "--rename-to", "/new"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## case-id: X"));
}

#[test]
fn test_rename_strip_prefix_with_empty_to() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["rename", m.to_str().unwrap(),
               "--rename-from", "/old/prefix/"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("  file1.txt"), "prefix should be stripped leaving bare filename");
}

#[test]
fn test_rename_output_to_file() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out_file = dir.path().join("renamed.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["rename", m.to_str().unwrap(),
               "--rename-from", "/old/prefix", "--rename-to", "/new",
               "-o", out_file.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("/new/file1.txt"));
}
```

**Implementation:**
```rust
// src/commands/rename.rs
use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn rename_paths(
    manifest_path: &Path,
    from: &str,
    to: &str,
    out: &mut impl Write,
) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;

    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() { continue; }
        if t.starts_with('#') || t.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        let parts: Vec<&str> = t.splitn(3, "  ").collect();
        if parts.len() == 3 {
            let algo = parts[0];
            let hash = parts[1];
            let path = parts[2].replace(from, to);
            writeln!(out, "{algo}  {hash}  {path}")?;
        } else {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}
```

Dispatch:
```rust
if let Mode::Rename = cli.mode() {
    let manifest_path = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("rename: missing manifest path"))?;
    let from = cli.rename_from.as_deref()
        .ok_or_else(|| anyhow::anyhow!("rename: --rename-from is required"))?;
    let to = cli.rename_to.as_deref().unwrap_or("");
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    commands::rename::rename_paths(manifest_path, from, to, &mut out)?;
    return Ok(());
}
```

**Commits:**
```bash
git add tests/rename_tests.rs
git commit -m "test(RED): add failing tests for blazehash rename"

git add src/commands/rename.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash rename — path find-and-replace in manifest entries"
```

---

### Task 3: `blazehash slice` — entries from index offset for count N

**Files:** Create `tests/slice_tests.rs`, `src/commands/slice.rs`. Modify the usual 3.

**What it does:** Emits entries starting at `--offset N` (0-based, default 0) for up to `--count M` entries. Headers always emitted. Complement to `head`/`tail` for arbitrary ranges.

**New CLI field:** `slice_offset: usize` → `#[arg(long = "offset", default_value = "0")]`. Reuses existing `--count`.

**Tests:**
```rust
// tests/slice_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir, n: usize) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    let mut content = String::from("## algorithm: blake3\n");
    for i in 1..=n {
        content.push_str(&format!("blake3  {:064x}  file{i:03}.txt\n", i));
    }
    fs::write(&p, &content).unwrap();
    p
}

#[test]
fn test_slice_offset_skips_first_entries() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 10);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["slice", m.to_str().unwrap(), "--offset", "5", "--count", "3"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let data: Vec<_> = s.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 3);
    assert!(data[0].contains("file006.txt"), "first result should be entry 6 (0-based offset 5)");
}

#[test]
fn test_slice_zero_offset_is_like_head() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 10);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["slice", m.to_str().unwrap(), "--offset", "0", "--count", "3"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let data: Vec<_> = s.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 3);
    assert!(data[0].contains("file001.txt"));
}

#[test]
fn test_slice_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 5);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["slice", m.to_str().unwrap(), "--offset", "1", "--count", "2"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## algorithm: blake3"));
}

#[test]
fn test_slice_offset_beyond_end_returns_empty() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 5);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["slice", m.to_str().unwrap(), "--offset", "100", "--count", "5"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let data: Vec<_> = s.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 0);
}

#[test]
fn test_slice_output_to_file() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 10);
    let out_file = dir.path().join("slice.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["slice", m.to_str().unwrap(), "--offset", "2", "--count", "2",
               "-o", out_file.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("file003.txt"));
}
```

**Implementation:**
```rust
// src/commands/slice.rs
use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn slice_manifest(
    manifest_path: &Path,
    offset: usize,
    count: usize,
    out: &mut impl Write,
) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<&str> = Vec::new();
    let mut entries: Vec<&str> = Vec::new();

    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() { continue; }
        if t.starts_with('#') || t.starts_with('%') {
            headers.push(line);
        } else {
            entries.push(line);
        }
    }

    for h in &headers { writeln!(out, "{h}")?; }

    for entry in entries.iter().skip(offset).take(count) {
        writeln!(out, "{entry}")?;
    }

    Ok(())
}
```

Dispatch:
```rust
if let Mode::Slice = cli.mode() {
    let manifest_path = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("slice: missing manifest path"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    commands::slice::slice_manifest(manifest_path, cli.slice_offset, cli.count, &mut out)?;
    return Ok(());
}
```

**Commits:**
```bash
git add tests/slice_tests.rs
git commit -m "test(RED): add failing tests for blazehash slice"

git add src/commands/slice.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash slice — emit entries from index offset for count N"
```

---

### Task 4: `blazehash stamp` — add/update timestamp headers

**Files:** Create `tests/stamp_tests.rs`, `src/commands/stamp.rs`. Modify the usual 3.

**What it does:** Adds `## stamped: <ISO-8601 UTC timestamp>` to the manifest header. If already present, updates it. Useful for chain-of-custody: record when a manifest was last processed.

No new CLI fields — uses existing `cli.output`.

**Tests:**
```rust
// tests/stamp_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("m.hash");
    fs::write(&p, "## case-id: X\nblake3  aaaa  file.txt\n").unwrap();
    p
}

#[test]
fn test_stamp_adds_stamped_header() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stamp", m.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## stamped:"), "should add stamped header");
}

#[test]
fn test_stamp_header_is_valid_timestamp() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stamp", m.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let ts_line = s.lines().find(|l| l.contains("## stamped:")).unwrap();
    let ts = ts_line.split_once(':').unwrap().1.trim();
    // Should look like a date: contains digits and hyphens
    assert!(ts.chars().any(|c| c.is_ascii_digit()), "timestamp should contain digits");
    assert!(ts.contains('-'), "timestamp should contain hyphens (ISO date)");
}

#[test]
fn test_stamp_preserves_existing_headers_and_entries() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stamp", m.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## case-id: X"));
    assert!(s.contains("blake3  aaaa  file.txt"));
}

#[test]
fn test_stamp_updates_existing_stamped_header() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("prestamped.hash");
    fs::write(&p, "## stamped: 2000-01-01T00:00:00Z\nblake3  aaaa  file.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["stamp", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let stamp_lines: Vec<_> = s.lines().filter(|l| l.contains("## stamped:")).collect();
    assert_eq!(stamp_lines.len(), 1, "should have exactly one stamped header");
    assert!(!stamp_lines[0].contains("2000-01-01"), "old timestamp should be replaced");
}

#[test]
fn test_stamp_output_to_file() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out_file = dir.path().join("stamped.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["stamp", m.to_str().unwrap(), "-o", out_file.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("## stamped:"));
}
```

**Implementation** (uses `std::time::SystemTime` — no chrono needed):
```rust
// src/commands/stamp.rs
use anyhow::Result;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Manual ISO-8601 UTC: YYYY-MM-DDTHH:MM:SSZ
    let s = secs;
    let (y, mo, d, h, mi, sec) = epoch_to_ymd_hms(s);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{sec:02}Z")
}

fn epoch_to_ymd_hms(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec = secs % 60;
    let mins = secs / 60;
    let min = mins % 60;
    let hours = mins / 60;
    let hour = hours % 24;
    let days = hours / 24;
    // Gregorian calendar calculation from days since epoch
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, hour, min, sec)
}

pub fn stamp_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let timestamp = now_iso8601();
    let mut stamped = false;

    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() { continue; }
        if let Some(rest) = t.strip_prefix("##") {
            if rest.trim().starts_with("stamped:") {
                writeln!(out, "## stamped: {timestamp}")?;
                stamped = true;
                continue;
            }
            writeln!(out, "{line}")?;
            continue;
        }
        if t.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        // First data line — insert stamp header before data if not yet written
        if !stamped {
            writeln!(out, "## stamped: {timestamp}")?;
            stamped = true;
        }
        writeln!(out, "{line}")?;
    }
    if !stamped {
        writeln!(out, "## stamped: {timestamp}")?;
    }
    Ok(())
}
```

Dispatch:
```rust
if let Mode::Stamp = cli.mode() {
    let manifest_path = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("stamp: missing manifest path"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    commands::stamp::stamp_manifest(manifest_path, &mut out)?;
    return Ok(());
}
```

**Commits:**
```bash
git add tests/stamp_tests.rs
git commit -m "test(RED): add failing tests for blazehash stamp"

git add src/commands/stamp.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash stamp — add/update stamped timestamp header in manifest"
```

---

### Task 5: `blazehash grep` — regex search across manifest entries

**Files:** Create `tests/grep_tests.rs`, `src/commands/grep_cmd.rs`. Modify the usual 3.

**What it does:** Searches manifest entries (full line) against a regex pattern. Prints matching lines. Headers preserved. Exits 1 if no matches. Case-insensitive with `--ignore-case`.

Note: The module is named `grep_cmd` (not `grep`) to avoid conflict with Rust's built-in `grep` concept and potential future stdlib conflicts.

**New CLI field:** `grep_pattern: Option<String>` → `#[arg(long = "pattern")]`

Check whether `regex` is available: run `grep -r "^regex" Cargo.toml`. If absent, add it: `cargo add regex`.

**Tests:**
```rust
// tests/grep_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("m.hash");
    fs::write(&p, concat!(
        "## case-id: X\n",
        "blake3  aaaa  docs/contract.pdf\n",
        "blake3  bbbb  images/photo.jpg\n",
        "blake3  cccc  docs/report.pdf\n",
        "sha256  dddd  bin/tool.exe\n",
    )).unwrap();
    p
}

#[test]
fn test_grep_matches_path_pattern() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["grep", m.to_str().unwrap(), "--pattern", r"\.pdf$"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let data: Vec<_> = s.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 2, "should match 2 PDF entries");
}

#[test]
fn test_grep_matches_hash_value() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["grep", m.to_str().unwrap(), "--pattern", "^blake3"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let data: Vec<_> = s.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 3, "should match 3 blake3 entries");
}

#[test]
fn test_grep_exits_nonzero_on_no_match() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    Command::cargo_bin("blazehash").unwrap()
        .args(["grep", m.to_str().unwrap(), "--pattern", "NOMATCH_XYZ_999"])
        .assert().failure();
}

#[test]
fn test_grep_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["grep", m.to_str().unwrap(), "--pattern", r"\.pdf"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## case-id: X"));
}

#[test]
fn test_grep_ignore_case_flag() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["grep", m.to_str().unwrap(), "--pattern", "BLAKE3", "--ignore-case"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let data: Vec<_> = s.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 3);
}
```

**Implementation:**
```rust
// src/commands/grep_cmd.rs
use anyhow::Result;
use regex::RegexBuilder;
use std::io::Write;
use std::path::Path;

pub fn grep_manifest(
    manifest_path: &Path,
    pattern: &str,
    ignore_case: bool,
    out: &mut impl Write,
) -> Result<usize> {
    let re = RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()?;

    let content = std::fs::read_to_string(manifest_path)?;
    let mut matches = 0usize;

    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() { continue; }
        if t.starts_with('#') || t.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        if re.is_match(t) {
            writeln!(out, "{line}")?;
            matches += 1;
        }
    }

    Ok(matches)
}
```

Add `pub mod grep_cmd;` to `src/commands/mod.rs`.

Dispatch:
```rust
if let Mode::Grep = cli.mode() {
    let manifest_path = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("grep: missing manifest path"))?;
    let pattern = cli.grep_pattern.as_deref()
        .ok_or_else(|| anyhow::anyhow!("grep: --pattern is required"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    let n = commands::grep_cmd::grep_manifest(
        manifest_path, pattern, cli.ignore_case, &mut out,
    )?;
    if n == 0 { std::process::exit(1); }
    return Ok(());
}
```

**Commits:**
```bash
git add tests/grep_tests.rs
git commit -m "test(RED): add failing tests for blazehash grep"

git add src/commands/grep_cmd.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash grep — regex search across manifest entries"
```

---

### Task 6: Final integration check + push

```bash
cargo test --all-features 2>&1 | grep -E "^test result|FAILED"
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -10
git push
```
