# Feature Batch 8 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Five manifest set-operation commands that treat manifests as queryable collections — sort, sample, intersect, subtract, and patch.

**Architecture:**
- All five are pure manifest transformations — no new dependencies required
- `sort` canonicalises entry order (stable deterministic sort by chosen field)
- `sample` draws a reproducible pseudo-random subset for spot-checking
- `intersect` and `subtract` implement classic set operations on manifest paths
- `patch` consumes the unified diff format emitted by `blazehash diff --patch` and applies it
- All follow the existing `Mode` enum dispatch pattern and `impl Write` output sink pattern

**Tech Stack:** Rust, `std::io`, `std::collections::{HashMap, HashSet}`, `rand` (already in Cargo.toml for GPU path — check; if absent use deterministic seeding via `std::collections::hash_map::DefaultHasher`)

---

### Task 1: `blazehash sort` — sort manifest entries by field

Sort all data lines in a manifest by a chosen field (path, hash, algo, or extension). Header/comment lines are always preserved at the top. Useful for canonicalising manifests before diffs.

**Files:**
- Create: `tests/sort_tests.rs`
- Create: `src/commands/sort.rs`
- Modify: `src/commands/mod.rs` — add `pub mod sort;`
- Modify: `src/cli.rs` — add `Sort` mode variant, `--sort-by` flag (`sort_by: Option<String>`)
- Modify: `src/main.rs` — add dispatch block

**Step 1: Write failing tests**

```rust
// tests/sort_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  zebra.txt\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  alpha.txt\n",
        "blake3  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  beta.bin\n",
    )).unwrap();
    p
}

#[test]
fn test_sort_by_path_default() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sort", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data: Vec<&str> = stdout.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 3);
    // alpha before beta before zebra
    let pos_alpha = data.iter().position(|l| l.contains("alpha.txt")).unwrap();
    let pos_beta  = data.iter().position(|l| l.contains("beta.bin")).unwrap();
    let pos_zebra = data.iter().position(|l| l.contains("zebra.txt")).unwrap();
    assert!(pos_alpha < pos_beta, "alpha must come before beta");
    assert!(pos_beta  < pos_zebra, "beta must come before zebra");
}

#[test]
fn test_sort_by_hash() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sort", manifest.to_str().unwrap(), "--sort-by", "hash"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data: Vec<&str> = stdout.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    // aaa before bbb before ccc
    let pos_a = data.iter().position(|l| l.contains("alpha.txt")).unwrap();
    let pos_b = data.iter().position(|l| l.contains("beta.bin")).unwrap();
    let pos_c = data.iter().position(|l| l.contains("zebra.txt")).unwrap();
    assert!(pos_a < pos_b && pos_b < pos_c, "entries must be sorted by hash");
}

#[test]
fn test_sort_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sort", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(first_line.starts_with("##"), "first line must be a header comment");
}

#[test]
fn test_sort_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("sorted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["sort", manifest.to_str().unwrap(), "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("alpha.txt"));
    assert!(content.contains("beta.bin"));
}

#[test]
fn test_sort_by_algo() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sort", manifest.to_str().unwrap(), "--sort-by", "algo"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data: Vec<&str> = stdout.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    // blake3 < sha256 alphabetically
    let pos_blake3 = data.iter().position(|l| l.contains("beta.bin")).unwrap();
    let pos_sha256_first = data.iter().position(|l| l.contains("sha256")).unwrap();
    assert!(pos_blake3 < pos_sha256_first, "blake3 must sort before sha256");
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test sort_tests 2>&1 | grep -E "error|FAILED|test result"
```

Expected: compile errors (subcommand/flag doesn't exist yet).

**Step 3: Implement `src/commands/sort.rs`**

```rust
//! Sort manifest entries by a chosen field (path, hash, algo, or ext).
//! Header/comment lines are emitted first, then sorted data lines.

use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn sort_manifest(manifest_path: &Path, by: &str, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;

    let mut headers: Vec<&str> = Vec::new();
    let mut entries: Vec<&str> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(line);
        } else {
            entries.push(line);
        }
    }

    entries.sort_by(|a, b| {
        let key_a = sort_key(a, by);
        let key_b = sort_key(b, by);
        key_a.cmp(&key_b)
    });

    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for e in &entries {
        writeln!(out, "{e}")?;
    }
    Ok(())
}

fn sort_key<'a>(line: &'a str, by: &str) -> &'a str {
    let parts: Vec<&str> = line.splitn(3, "  ").collect();
    if parts.len() != 3 {
        return line;
    }
    match by {
        "hash" => parts[1].trim(),
        "algo" => parts[0].trim(),
        "ext"  => {
            let path = parts[2].trim();
            // Return the extension portion, or full path if none
            match path.rfind('.') {
                Some(i) => &path[i..],
                None => path,
            }
        }
        _ => parts[2].trim(), // default: sort by path
    }
}

pub fn validate_sort_by(by: &str) -> Result<()> {
    match by {
        "path" | "hash" | "algo" | "ext" => Ok(()),
        other => bail!("unknown sort field '{other}'; supported: path, hash, algo, ext"),
    }
}
```

**Step 4: Wire into CLI**

Add to `Cli` struct in `src/cli.rs`:
```rust
/// Field to sort by for sort subcommand: path, hash, algo, ext (default: path)
#[arg(long = "sort-by", value_name = "FIELD", default_value = "path")]
pub sort_by: String,
```

Add `Sort` to `Mode` enum. Add detection in `mode()`:
```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("sort")) {
    Mode::Sort
```

Add to `src/commands/mod.rs`:
```rust
pub mod sort;
```

Add dispatch in `src/main.rs` (before `Mode::Vt` block):
```rust
if let Mode::Sort = cli.mode() {
    let manifest = cli
        .paths
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash sort <manifest> [--sort-by path|hash|algo|ext]"))?;
    commands::sort::validate_sort_by(&cli.sort_by)?;
    if let Some(out_path) = &output {
        let mut f = std::fs::File::create(out_path)?;
        commands::sort::sort_manifest(&manifest, &cli.sort_by, &mut f)?;
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        commands::sort::sort_manifest(&manifest, &cli.sort_by, &mut handle)?;
    }
    return Ok(());
}
```

Add `Mode::Sort => unreachable!()` to exhaustive match.

**Step 5: Run to confirm GREEN**

```bash
cargo test --all-features --test sort_tests 2>&1 | grep -E "FAILED|ok|test result"
```

Expected: `test result: ok. 5 passed; 0 failed`

**Step 6: Commit**

```bash
git add tests/sort_tests.rs
git commit -m "test(RED): add failing tests for blazehash sort"

git add src/commands/sort.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash sort — sort manifest entries by path/hash/algo/ext"
```

---

### Task 2: `blazehash sample` — random sample of N entries

Draw N pseudo-random data entries from a manifest, preserving header lines. Uses a seed derived from the manifest path for reproducibility. Default N = 10 (reuses existing `--count`/`-n` flag).

**Files:**
- Create: `tests/sample_tests.rs`
- Create: `src/commands/sample.rs`
- Modify: `src/commands/mod.rs` — add `pub mod sample;`
- Modify: `src/cli.rs` — add `Sample` mode variant
- Modify: `src/main.rs` — add dispatch block

Note: No new CLI flags needed — reuse the existing `--count`/`-n` field (already on `Cli` with default 10).

**Step 1: Write failing tests**

```rust
// tests/sample_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_large_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("large.hash");
    let mut content = String::from("## case: LARGE\n");
    for i in 0..20u8 {
        content.push_str(&format!(
            "sha256  {:0>64x}  file{:02}.txt\n",
            i as u64, i
        ));
    }
    fs::write(&p, &content).unwrap();
    p
}

#[test]
fn test_sample_count_limits_output() {
    let dir = TempDir::new().unwrap();
    let manifest = write_large_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sample", manifest.to_str().unwrap(), "--count", "5"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data: Vec<_> = stdout.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 5, "sample --count 5 must return exactly 5 entries");
}

#[test]
fn test_sample_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_large_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sample", manifest.to_str().unwrap(), "--count", "3"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## case: LARGE"), "headers must be preserved");
}

#[test]
fn test_sample_count_larger_than_manifest_returns_all() {
    let dir = TempDir::new().unwrap();
    let manifest = write_large_manifest(&dir);
    // 20 entries in manifest, request 50
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sample", manifest.to_str().unwrap(), "--count", "50"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data: Vec<_> = stdout.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 20, "requesting more than available must return all entries");
}

#[test]
fn test_sample_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_large_manifest(&dir);
    let out_path = dir.path().join("sample.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["sample", manifest.to_str().unwrap(), "--count", "4",
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    let data_lines: Vec<_> = content.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data_lines.len(), 4);
}

#[test]
fn test_sample_entries_are_valid_manifest_lines() {
    let dir = TempDir::new().unwrap();
    let manifest = write_large_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["sample", manifest.to_str().unwrap(), "--count", "5"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines().filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#')) {
        let parts: Vec<&str> = line.splitn(3, "  ").collect();
        assert_eq!(parts.len(), 3, "sampled entry must be valid manifest line: {line}");
    }
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test sample_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/commands/sample.rs`**

```rust
//! Draw a pseudo-random sample of N entries from a manifest.
//! Uses a deterministic Fisher-Yates shuffle seeded from the manifest path.

use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn sample_manifest(manifest_path: &Path, count: usize, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;

    let mut headers: Vec<&str> = Vec::new();
    let mut entries: Vec<&str> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(line);
        } else {
            entries.push(line);
        }
    }

    // Deterministic LCG seed derived from manifest path bytes
    let seed: u64 = manifest_path
        .to_string_lossy()
        .bytes()
        .fold(0x517cc1b727220a95u64, |acc, b| {
            acc.wrapping_mul(6364136223846793005).wrapping_add(b as u64)
        });

    let take = count.min(entries.len());
    let sampled = lcg_sample(&entries, take, seed);

    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for e in sampled {
        writeln!(out, "{e}")?;
    }
    Ok(())
}

/// Simple LCG-based reservoir selection (no external crate needed).
fn lcg_sample<'a>(entries: &[&'a str], take: usize, seed: u64) -> Vec<&'a str> {
    if take >= entries.len() {
        return entries.to_vec();
    }
    let mut rng = seed;
    let mut indices: Vec<usize> = (0..entries.len()).collect();

    // Partial Fisher-Yates: shuffle only the first `take` positions
    for i in 0..take {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = i + (rng >> 33) as usize % (entries.len() - i);
        indices.swap(i, j);
    }

    indices[..take].iter().map(|&i| entries[i]).collect()
}
```

**Step 4: Wire into CLI**

Add `Sample` to `Mode` enum in `src/cli.rs`. Add detection in `mode()`:
```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("sample")) {
    Mode::Sample
```

No new flags — reuse `cli.count` (already `--count`/`-n`, default 10).

Add to `src/commands/mod.rs`:
```rust
pub mod sample;
```

Add dispatch in `src/main.rs`:
```rust
if let Mode::Sample = cli.mode() {
    let manifest = cli
        .paths
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash sample <manifest> [--count N]"))?;
    if let Some(out_path) = &output {
        let mut f = std::fs::File::create(out_path)?;
        commands::sample::sample_manifest(&manifest, cli.count, &mut f)?;
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        commands::sample::sample_manifest(&manifest, cli.count, &mut handle)?;
    }
    return Ok(());
}
```

Add `Mode::Sample => unreachable!()` to exhaustive match.

**Step 5: Run to confirm GREEN**

```bash
cargo test --all-features --test sample_tests 2>&1 | grep -E "FAILED|ok|test result"
```

Expected: `test result: ok. 5 passed; 0 failed`

**Step 6: Commit**

```bash
git add tests/sample_tests.rs
git commit -m "test(RED): add failing tests for blazehash sample"

git add src/commands/sample.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash sample — pseudo-random sample of N manifest entries"
```

---

### Task 3: `blazehash intersect` — entries common to two manifests

Output entries whose **path** appears in both manifests. The hash and algo from the **first** manifest are used in the output. Useful for finding the overlap between two evidence sets.

**Files:**
- Create: `tests/intersect_tests.rs`
- Create: `src/commands/intersect.rs`
- Modify: `src/commands/mod.rs` — add `pub mod intersect;`
- Modify: `src/cli.rs` — add `Intersect` mode variant
- Modify: `src/main.rs` — add dispatch block

No new flags needed — `paths[1]` is manifest A, `paths[2]` is manifest B.

**Step 1: Write failing tests**

```rust
// tests/intersect_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest_a(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("a.hash");
    fs::write(&p, concat!(
        "## manifest: A\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  shared.txt\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  only_in_a.txt\n",
        "sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  also_shared.pdf\n",
    )).unwrap();
    p
}

fn write_manifest_b(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("b.hash");
    fs::write(&p, concat!(
        "## manifest: B\n",
        "sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  shared.txt\n",
        "sha256  eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  only_in_b.txt\n",
        "sha256  ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  also_shared.pdf\n",
    )).unwrap();
    p
}

#[test]
fn test_intersect_finds_common_paths() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["intersect", a.to_str().unwrap(), b.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("shared.txt"), "shared path must appear");
    assert!(stdout.contains("also_shared.pdf"), "second shared path must appear");
    assert!(!stdout.contains("only_in_a.txt"), "a-only path must not appear");
    assert!(!stdout.contains("only_in_b.txt"), "b-only path must not appear");
}

#[test]
fn test_intersect_uses_hash_from_first_manifest() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["intersect", a.to_str().unwrap(), b.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // shared.txt hash in A is "aaa...", in B is "ddd..."
    assert!(stdout.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "output must use hash from first manifest");
    assert!(!stdout.contains("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
        "hash from second manifest must not appear for shared.txt");
}

#[test]
fn test_intersect_no_common_paths_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.hash");
    let b = dir.path().join("b.hash");
    fs::write(&a, "sha256  aaaa  file_a.txt\n").unwrap();
    fs::write(&b, "sha256  bbbb  file_b.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["intersect", a.to_str().unwrap(), b.to_str().unwrap()])
        .output().unwrap();
    // exit 1 when no intersection (like grep)
    assert!(!out.status.success(), "empty intersection must exit nonzero");
}

#[test]
fn test_intersect_output_to_file() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out_path = dir.path().join("common.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["intersect", a.to_str().unwrap(), b.to_str().unwrap(),
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("shared.txt"));
}

#[test]
fn test_intersect_missing_second_arg_fails() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.hash");
    fs::write(&a, "sha256  aaaa  f.txt\n").unwrap();
    Command::cargo_bin("blazehash").unwrap()
        .args(["intersect", a.to_str().unwrap()])
        .assert().failure();
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test intersect_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/commands/intersect.rs`**

```rust
//! Output entries whose path appears in both manifests.
//! Hash and algo are taken from the first (left) manifest.

use anyhow::Result;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

pub fn intersect_manifests(
    left_path: &Path,
    right_path: &Path,
    out: &mut impl Write,
) -> Result<usize> {
    let left  = std::fs::read_to_string(left_path)?;
    let right = std::fs::read_to_string(right_path)?;

    // Build set of paths from right manifest
    let right_paths: HashSet<String> = right
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with('%') {
                return None;
            }
            let parts: Vec<&str> = t.splitn(3, "  ").collect();
            if parts.len() == 3 {
                Some(parts[2].trim().to_string())
            } else {
                None
            }
        })
        .collect();

    let mut matched = 0;
    for line in left.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            let path = parts[2].trim();
            if right_paths.contains(path) {
                writeln!(out, "{line}")?;
                matched += 1;
            }
        }
    }
    Ok(matched)
}
```

**Step 4: Wire into CLI**

Add `Intersect` to `Mode` enum. Add detection in `mode()`:
```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("intersect")) {
    Mode::Intersect
```

Add to `src/commands/mod.rs`:
```rust
pub mod intersect;
```

Add dispatch in `src/main.rs`:
```rust
if let Mode::Intersect = cli.mode() {
    let left = cli
        .paths
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash intersect <manifest_a> <manifest_b>"))?;
    let right = cli
        .paths
        .get(2)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash intersect <manifest_a> <manifest_b>"))?;
    let matched = if let Some(out_path) = &output {
        let mut f = std::fs::File::create(out_path)?;
        commands::intersect::intersect_manifests(&left, &right, &mut f)?
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        commands::intersect::intersect_manifests(&left, &right, &mut handle)?
    };
    if matched == 0 {
        std::process::exit(1);
    }
    return Ok(());
}
```

Add `Mode::Intersect => unreachable!()` to exhaustive match.

**Step 5: Run to confirm GREEN**

```bash
cargo test --all-features --test intersect_tests 2>&1 | grep -E "FAILED|ok|test result"
```

Expected: `test result: ok. 5 passed; 0 failed`

**Step 6: Commit**

```bash
git add tests/intersect_tests.rs
git commit -m "test(RED): add failing tests for blazehash intersect"

git add src/commands/intersect.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash intersect — entries common to two manifests"
```

---

### Task 4: `blazehash subtract` — entries in A not in B

Output entries from manifest A whose **path** does not appear in manifest B. The complement of intersect. Useful for finding what's new/unique to an evidence set vs. a baseline.

**Files:**
- Create: `tests/subtract_tests.rs`
- Create: `src/commands/subtract.rs`
- Modify: `src/commands/mod.rs` — add `pub mod subtract;`
- Modify: `src/cli.rs` — add `Subtract` mode variant
- Modify: `src/main.rs` — add dispatch block

**Step 1: Write failing tests**

```rust
// tests/subtract_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest_a(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("a.hash");
    fs::write(&p, concat!(
        "## manifest: A\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  shared.txt\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  only_in_a.txt\n",
        "sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  also_shared.pdf\n",
    )).unwrap();
    p
}

fn write_manifest_b(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("b.hash");
    fs::write(&p, concat!(
        "## manifest: B\n",
        "sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  shared.txt\n",
        "sha256  eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  only_in_b.txt\n",
        "sha256  ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  also_shared.pdf\n",
    )).unwrap();
    p
}

#[test]
fn test_subtract_returns_a_minus_b() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["subtract", a.to_str().unwrap(), b.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("only_in_a.txt"), "a-only path must appear");
    assert!(!stdout.contains("shared.txt"), "shared path must be subtracted");
    assert!(!stdout.contains("also_shared.pdf"), "also-shared must be subtracted");
    assert!(!stdout.contains("only_in_b.txt"), "b-only path must never appear");
}

#[test]
fn test_subtract_empty_result_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    // A is a subset of B — result is empty
    let a = dir.path().join("a.hash");
    let b = dir.path().join("b.hash");
    fs::write(&a, "sha256  aaaa  shared.txt\n").unwrap();
    fs::write(&b, concat!(
        "sha256  aaaa  shared.txt\n",
        "sha256  bbbb  extra.txt\n",
    )).unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["subtract", a.to_str().unwrap(), b.to_str().unwrap()])
        .output().unwrap();
    assert!(!out.status.success(), "empty result must exit nonzero");
}

#[test]
fn test_subtract_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["subtract", a.to_str().unwrap(), b.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## manifest: A"), "headers from A must be preserved");
}

#[test]
fn test_subtract_output_to_file() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest_a(&dir);
    let b = write_manifest_b(&dir);
    let out_path = dir.path().join("diff.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["subtract", a.to_str().unwrap(), b.to_str().unwrap(),
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("only_in_a.txt"));
}

#[test]
fn test_subtract_missing_second_arg_fails() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a.hash");
    fs::write(&a, "sha256  aaaa  f.txt\n").unwrap();
    Command::cargo_bin("blazehash").unwrap()
        .args(["subtract", a.to_str().unwrap()])
        .assert().failure();
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test subtract_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/commands/subtract.rs`**

```rust
//! Output entries from manifest A whose path does not appear in manifest B.
//! This is the set difference A \ B.

use anyhow::Result;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

pub fn subtract_manifests(
    left_path: &Path,
    right_path: &Path,
    out: &mut impl Write,
) -> Result<usize> {
    let left  = std::fs::read_to_string(left_path)?;
    let right = std::fs::read_to_string(right_path)?;

    // Build set of paths from right manifest to exclude
    let right_paths: HashSet<String> = right
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with('%') {
                return None;
            }
            let parts: Vec<&str> = t.splitn(3, "  ").collect();
            if parts.len() == 3 {
                Some(parts[2].trim().to_string())
            } else {
                None
            }
        })
        .collect();

    let mut kept = 0;
    for line in left.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            let path = parts[2].trim();
            if !right_paths.contains(path) {
                writeln!(out, "{line}")?;
                kept += 1;
            }
        }
    }
    Ok(kept)
}
```

**Step 4: Wire into CLI**

Add `Subtract` to `Mode` enum. Add detection in `mode()`:
```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("subtract")) {
    Mode::Subtract
```

Add to `src/commands/mod.rs`:
```rust
pub mod subtract;
```

Add dispatch in `src/main.rs`:
```rust
if let Mode::Subtract = cli.mode() {
    let left = cli
        .paths
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash subtract <manifest_a> <manifest_b>"))?;
    let right = cli
        .paths
        .get(2)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash subtract <manifest_a> <manifest_b>"))?;
    let kept = if let Some(out_path) = &output {
        let mut f = std::fs::File::create(out_path)?;
        commands::subtract::subtract_manifests(&left, &right, &mut f)?
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        commands::subtract::subtract_manifests(&left, &right, &mut handle)?
    };
    if kept == 0 {
        std::process::exit(1);
    }
    return Ok(());
}
```

Add `Mode::Subtract => unreachable!()` to exhaustive match.

**Step 5: Run to confirm GREEN**

```bash
cargo test --all-features --test subtract_tests 2>&1 | grep -E "FAILED|ok|test result"
```

Expected: `test result: ok. 5 passed; 0 failed`

**Step 6: Commit**

```bash
git add tests/subtract_tests.rs
git commit -m "test(RED): add failing tests for blazehash subtract"

git add src/commands/subtract.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash subtract — entries in A not present in B (set difference)"
```

---

### Task 5: `blazehash apply-patch` — apply a diff patch to a manifest

Consume a unified diff patch file (as produced by `blazehash diff --patch`) and apply it to a manifest, producing an updated manifest. Lines starting with `-` are removed; lines starting with `+` are added. Preserves header comments.

**Files:**
- Create: `tests/apply_patch_tests.rs`
- Create: `src/commands/apply_patch.rs`
- Modify: `src/commands/mod.rs` — add `pub mod apply_patch;`
- Modify: `src/cli.rs` — add `ApplyPatch` mode variant
- Modify: `src/main.rs` — add dispatch block

Detection: `paths[0] == "apply-patch"`, `paths[1]` = manifest, `paths[2]` = patch file.

**Step 1: Write failing tests**

```rust
// tests/apply_patch_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("evidence.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  unchanged.txt\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  modified.txt\n",
        "sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  removed.txt\n",
    )).unwrap();
    p
}

fn write_patch(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("changes.diff");
    fs::write(&p, concat!(
        "--- evidence.hash\n",
        "+++ evidence.hash\n",
        "-sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  modified.txt\n",
        "+sha256  9999999999999999999999999999999999999999999999999999999999999999  modified.txt\n",
        "-sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  removed.txt\n",
        "+sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  added.txt\n",
    )).unwrap();
    p
}

#[test]
fn test_apply_patch_removes_minus_lines() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let patch = write_patch(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["apply-patch", manifest.to_str().unwrap(), patch.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success(), "apply-patch failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        "removed entry (old hash) must be gone");
    assert!(!stdout.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        "modified old hash must be gone");
}

#[test]
fn test_apply_patch_adds_plus_lines() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let patch = write_patch(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["apply-patch", manifest.to_str().unwrap(), patch.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("added.txt"), "added entry must appear");
    assert!(stdout.contains("9999999999999999999999999999999999999999999999999999999999999999"),
        "modified new hash must appear");
}

#[test]
fn test_apply_patch_preserves_unchanged_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let patch = write_patch(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["apply-patch", manifest.to_str().unwrap(), patch.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("unchanged.txt"), "unchanged entry must be preserved");
    assert!(stdout.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "unchanged hash must be preserved");
}

#[test]
fn test_apply_patch_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let patch = write_patch(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["apply-patch", manifest.to_str().unwrap(), patch.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## case: CASE-001"), "headers must be preserved");
}

#[test]
fn test_apply_patch_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let patch = write_patch(&dir);
    let out_path = dir.path().join("updated.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["apply-patch", manifest.to_str().unwrap(), patch.to_str().unwrap(),
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("unchanged.txt"));
    assert!(content.contains("added.txt"));
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test apply_patch_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/commands/apply_patch.rs`**

```rust
//! Apply a blazehash diff patch file to a manifest.
//!
//! Patch format (as produced by `blazehash diff --patch`):
//!   `--- old_manifest`   — ignored (diff header)
//!   `+++ new_manifest`   — ignored (diff header)
//!   `-algo  hash  path`  — remove this entry (matched by full line content)
//!   `+algo  hash  path`  — add this entry
//!   ` algo  hash  path`  — context line, ignored
//!
//! Algorithm:
//!   1. Parse patch: build removal set (exact line strings) and additions list.
//!   2. Stream the manifest: emit header lines unchanged; emit data lines that
//!      are NOT in the removal set.
//!   3. Append addition lines at the end (before any trailing blank lines).

use anyhow::Result;
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

pub fn apply_patch(
    manifest_path: &Path,
    patch_path: &Path,
    out: &mut impl Write,
) -> Result<()> {
    let manifest = std::fs::read_to_string(manifest_path)?;
    let patch    = std::fs::read_to_string(patch_path)?;

    let mut removals: HashSet<String> = HashSet::new();
    let mut additions: Vec<String> = Vec::new();

    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix('-') {
            // Skip `--- filename` diff headers
            if rest.starts_with("--") {
                continue;
            }
            removals.insert(rest.to_string());
        } else if let Some(rest) = line.strip_prefix('+') {
            // Skip `+++ filename` diff headers
            if rest.starts_with("++") {
                continue;
            }
            additions.push(rest.to_string());
        }
        // Context lines (space-prefixed) and other lines are ignored
    }

    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        if !removals.contains(trimmed) {
            writeln!(out, "{line}")?;
        }
    }

    for addition in &additions {
        writeln!(out, "{addition}")?;
    }

    Ok(())
}
```

**Step 4: Wire into CLI**

Add `ApplyPatch` to `Mode` enum. Add detection in `mode()` — note this is a two-word subcommand `apply-patch`:
```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("apply-patch")) {
    Mode::ApplyPatch
```

Add to `src/commands/mod.rs`:
```rust
pub mod apply_patch;
```

Add dispatch in `src/main.rs`:
```rust
if let Mode::ApplyPatch = cli.mode() {
    let manifest = cli
        .paths
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash apply-patch <manifest> <patch-file>"))?;
    let patch_file = cli
        .paths
        .get(2)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash apply-patch <manifest> <patch-file>"))?;
    if let Some(out_path) = &output {
        let mut f = std::fs::File::create(out_path)?;
        commands::apply_patch::apply_patch(&manifest, &patch_file, &mut f)?;
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        commands::apply_patch::apply_patch(&manifest, &patch_file, &mut handle)?;
    }
    return Ok(());
}
```

Add `Mode::ApplyPatch => unreachable!()` to exhaustive match.

**Step 5: Run to confirm GREEN**

```bash
cargo test --all-features --test apply_patch_tests 2>&1 | grep -E "FAILED|ok|test result"
```

Expected: `test result: ok. 5 passed; 0 failed`

**Step 6: Commit**

```bash
git add tests/apply_patch_tests.rs
git commit -m "test(RED): add failing tests for blazehash apply-patch"

git add src/commands/apply_patch.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash apply-patch — apply diff patch to update a manifest"
```

---

### Task 6: Final integration check

**Step 1: Full test suite**

```bash
cargo test --all-features 2>&1 | grep -E "^test result|FAILED"
```

Expected: all green.

**Step 2: Clippy**

```bash
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -20
```

Expected: no errors.

**Step 3: Push**

```bash
git push
```

---

## Summary

| Task | Subcommand | Purpose | Key file |
|------|-----------|---------|----------|
| 1 | `blazehash sort` | Sort entries by path/hash/algo/ext | `src/commands/sort.rs` |
| 2 | `blazehash sample` | Pseudo-random sample of N entries | `src/commands/sample.rs` |
| 3 | `blazehash intersect` | Entries whose path appears in both | `src/commands/intersect.rs` |
| 4 | `blazehash subtract` | Entries in A not in B (set difference) | `src/commands/subtract.rs` |
| 5 | `blazehash apply-patch` | Apply a diff patch to update a manifest | `src/commands/apply_patch.rs` |
| 6 | Integration check | Full test suite + clippy + push | — |

All tasks are pure manifest transformations — no new Cargo dependencies required.
