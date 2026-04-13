# blazehash Feature Batch 9 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Five manifest-lifecycle subcommands that complete the core forensic verification and metadata management workflow.

**Architecture:** All commands follow the established `Mode` dispatch pattern in `src/cli.rs` + `src/main.rs`, with library functions in `src/commands/<name>.rs` taking `&mut impl Write`. Two separate commits per task: RED (failing tests) then GREEN (passing implementation).

**Tech Stack:** Rust std only — no new dependencies needed.

---

### Task 1: `blazehash verify` — re-hash files and check against manifest

**Files:**
- Create: `tests/verify_tests.rs`
- Create: `src/commands/verify.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs`
- Modify: `src/main.rs`

**What it does:**
Re-hashes each file listed in the manifest and compares the computed hash to the stored hash. Prints `PASS <path>` or `FAIL <path>  expected=<stored>  got=<computed>` for each entry. Exits 0 if all pass, exits 1 if any mismatch or file is missing.

Optionally filter to a specific algorithm with `--verify-algo <algo>`.

**Step 1: Write the failing tests (RED)**

```rust
// tests/verify_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_file_and_manifest(dir: &TempDir, content: &[u8], algo: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let file_path = dir.path().join("evidence.bin");
    fs::write(&file_path, content).unwrap();

    // Hash it with blazehash to get the correct hash
    let hash_out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--algo", algo, file_path.to_str().unwrap()])
        .output()
        .unwrap();
    let manifest_path = dir.path().join("evidence.hash");
    fs::write(&manifest_path, &hash_out.stdout).unwrap();
    (file_path, manifest_path)
}

#[test]
fn test_verify_passes_when_file_matches() {
    let dir = TempDir::new().unwrap();
    let (_file, manifest) = write_file_and_manifest(&dir, b"hello world", "blake3");
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["verify", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "verify should exit 0 when all match");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PASS"), "should print PASS");
}

#[test]
fn test_verify_fails_when_file_modified() {
    let dir = TempDir::new().unwrap();
    let (file, manifest) = write_file_and_manifest(&dir, b"original content", "blake3");
    // Tamper with the file
    fs::write(&file, b"tampered content").unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["verify", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "verify should exit 1 on mismatch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FAIL"), "should print FAIL for tampered file");
}

#[test]
fn test_verify_fails_when_file_missing() {
    let dir = TempDir::new().unwrap();
    let (file, manifest) = write_file_and_manifest(&dir, b"data", "blake3");
    fs::remove_file(&file).unwrap();
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["verify", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "verify should exit 1 when file missing");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("MISS") || stdout.contains("FAIL"), "should indicate missing file");
}

#[test]
fn test_verify_algo_filter() {
    // Write a manifest with two algorithms, then verify only one
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("data.bin");
    fs::write(&file_path, b"test data").unwrap();
    let hash_out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["--algo", "blake3,sha256", file_path.to_str().unwrap()])
        .output()
        .unwrap();
    let manifest_path = dir.path().join("data.hash");
    fs::write(&manifest_path, &hash_out.stdout).unwrap();

    // verify only blake3
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["verify", manifest_path.to_str().unwrap(), "--verify-algo", "blake3"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("blake3") || stdout.contains("PASS"));
}

#[test]
fn test_verify_missing_manifest_fails() {
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["verify", "/nonexistent/path.hash"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
```

**Step 2: Run tests to confirm RED**

```bash
cargo test --all-features --test verify_tests 2>&1 | tail -10
```
Expected: compile error or FAILED (verify subcommand doesn't exist yet)

**Step 3: Write the implementation**

```rust
// src/commands/verify.rs
use crate::algorithm::Algorithm;
use anyhow::Result;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;

pub struct VerifyResult {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub missing: usize,
}

pub fn verify_manifest(
    manifest_path: &Path,
    algo_filter: Option<&str>,
    out: &mut impl Write,
) -> Result<VerifyResult> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut result = VerifyResult { total: 0, passed: 0, failed: 0, missing: 0 };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue;
        }
        let algo_str = parts[0].trim();
        let stored_hash = parts[1].trim();
        let path_str = parts[2].trim();

        // Apply algo filter
        if let Some(filter) = algo_filter {
            if !algo_str.eq_ignore_ascii_case(filter) {
                continue;
            }
        }

        result.total += 1;

        let algo = match Algorithm::from_str(algo_str) {
            Ok(a) => a,
            Err(_) => {
                writeln!(out, "SKIP  {path_str}  (unknown algorithm: {algo_str})")?;
                continue;
            }
        };

        let file_path = Path::new(path_str);
        if !file_path.exists() {
            writeln!(out, "MISS  {path_str}")?;
            result.missing += 1;
            result.failed += 1;
            continue;
        }

        let bytes = std::fs::read(file_path)?;
        let computed = crate::algorithm::hash_bytes(&bytes, algo);

        if computed == stored_hash {
            writeln!(out, "PASS  {path_str}")?;
            result.passed += 1;
        } else {
            writeln!(out, "FAIL  {path_str}  expected={stored_hash}  got={computed}")?;
            result.failed += 1;
        }
    }

    Ok(result)
}
```

Add to `src/commands/mod.rs`:
```rust
pub mod verify;
```

Add to `src/cli.rs` in the `Cli` struct:
```rust
#[arg(long = "verify-algo")]
pub verify_algo: Option<String>,
```

Add `Verify` to the `Mode` enum detection in `mode()`:
```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("verify")) {
    Mode::Verify
```

Add to `src/main.rs` dispatch:
```rust
if let Mode::Verify = cli.mode() {
    let manifest_path = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("verify: missing manifest path"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    let result = blazehash::commands::verify::verify_manifest(
        manifest_path,
        cli.verify_algo.as_deref(),
        &mut out,
    )?;
    if result.failed > 0 {
        std::process::exit(1);
    }
    return Ok(());
}
```

Also add `Mode::Verify => unreachable!()` to the exhaustive match.

**Step 4: Run tests to confirm GREEN**

```bash
cargo test --all-features --test verify_tests 2>&1 | tail -10
```
Expected: all 5 pass

**Step 5: Commit**

```bash
# RED commit first (already done in step 2 run)
git add tests/verify_tests.rs
git commit -m "test(RED): add failing tests for blazehash verify"

# GREEN commit
git add src/commands/verify.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash verify — re-hash files and compare against manifest"
```

---

### Task 2: `blazehash tail` — last N manifest entries

**Files:**
- Create: `tests/tail_tests.rs`
- Create: `src/commands/tail.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`

**What it does:** Prints the last `--count` (default 10) data entries from a manifest, always prepending header/comment lines. Symmetric with `head`.

**Step 1: Write the failing tests (RED)**

```rust
// tests/tail_tests.rs
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
fn test_tail_default_10() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 15);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tail", m.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    let data_lines: Vec<_> = s.lines().filter(|l| !l.starts_with('#') && !l.starts_with('%') && !l.is_empty()).collect();
    assert_eq!(data_lines.len(), 10, "default tail should return 10 entries");
    // Should be the LAST 10 entries
    assert!(data_lines.last().unwrap().contains("file015.txt"), "last entry should be file015");
}

#[test]
fn test_tail_count_3() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 10);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tail", m.to_str().unwrap(), "--count", "3"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    let data_lines: Vec<_> = s.lines().filter(|l| !l.starts_with('#') && !l.starts_with('%') && !l.is_empty()).collect();
    assert_eq!(data_lines.len(), 3);
    assert!(data_lines.last().unwrap().contains("file010.txt"));
}

#[test]
fn test_tail_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 5);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tail", m.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## algorithm: blake3"), "headers must be preserved");
}

#[test]
fn test_tail_count_larger_than_manifest_returns_all() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 4);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tail", m.to_str().unwrap(), "--count", "100"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    let data_lines: Vec<_> = s.lines().filter(|l| !l.starts_with('#') && !l.starts_with('%') && !l.is_empty()).collect();
    assert_eq!(data_lines.len(), 4, "should return all 4 entries when count > total");
}

#[test]
fn test_tail_output_to_file() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 5);
    let out_file = dir.path().join("out.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tail", m.to_str().unwrap(), "-o", out_file.to_str().unwrap()])
        .assert()
        .success();
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("file005.txt"));
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test tail_tests 2>&1 | tail -10
```

**Step 3: Implement**

```rust
// src/commands/tail.rs
use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn tail_manifest(manifest_path: &Path, count: usize, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers = Vec::new();
    let mut entries = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(line);
        } else {
            entries.push(line);
        }
    }

    for h in &headers {
        writeln!(out, "{h}")?;
    }

    let start = entries.len().saturating_sub(count);
    for entry in &entries[start..] {
        writeln!(out, "{entry}")?;
    }

    Ok(())
}
```

CLI additions follow the same pattern as `head` — reuse the `--count`/`-n` flag (it's shared) and add `Tail` to `Mode`.

**Step 4: Confirm GREEN**

```bash
cargo test --all-features --test tail_tests 2>&1 | tail -10
```

**Step 5: Commit**

```bash
git add tests/tail_tests.rs
git commit -m "test(RED): add failing tests for blazehash tail"

git add src/commands/tail.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash tail — last N manifest entries"
```

---

### Task 3: `blazehash info` — display manifest metadata

**Files:**
- Create: `tests/info_tests.rs`
- Create: `src/commands/info.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`

**What it does:** Parses and displays all `## key: value` header lines plus computed stats (entry count, unique paths, algorithms used). Supports `--json`.

**Step 1: Write the failing tests (RED)**

```rust
// tests/info_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, "## case-id: CASE-001\n## examiner: Alice\n## algorithm: blake3\nblake3  aaaa  file1.txt\nblake3  bbbb  file2.txt\n").unwrap();
    p
}

#[test]
fn test_info_shows_case_id() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["info", m.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("CASE-001"), "should display case-id value");
}

#[test]
fn test_info_shows_entry_count() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["info", m.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains('2'), "should show 2 entries");
}

#[test]
fn test_info_json_output() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["info", m.to_str().unwrap(), "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    let v: serde_json::Value = serde_json::from_str(&s).expect("should be valid JSON");
    assert_eq!(v["headers"]["case-id"], "CASE-001");
    assert_eq!(v["entries"], 2);
}

#[test]
fn test_info_shows_algorithms() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["info", m.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("blake3"), "should list algorithms used");
}

#[test]
fn test_info_missing_manifest_fails() {
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["info", "/no/such/file.hash"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test info_tests 2>&1 | tail -10
```

**Step 3: Implement**

```rust
// src/commands/info.rs
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestInfo {
    pub path: String,
    pub headers: HashMap<String, String>,
    pub entries: usize,
    pub algorithms: HashMap<String, usize>,
    pub unique_paths: usize,
}

pub fn parse_info(manifest_path: &Path) -> Result<ManifestInfo> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut entries = 0usize;
    let mut algorithms: HashMap<String, usize> = HashMap::new();
    let mut paths: std::collections::HashSet<String> = Default::default();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("##") {
            let rest = rest.trim();
            if let Some((k, v)) = rest.split_once(':') {
                headers.insert(k.trim().to_string(), v.trim().to_string());
            }
            continue;
        }
        if trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            entries += 1;
            let algo = parts[0].trim().to_lowercase();
            *algorithms.entry(algo).or_insert(0) += 1;
            paths.insert(parts[2].trim().to_string());
        }
    }

    Ok(ManifestInfo {
        path: manifest_path.display().to_string(),
        headers,
        entries,
        algorithms,
        unique_paths: paths.len(),
    })
}

pub fn run_info(manifest_path: &Path, json: bool, out: &mut impl Write) -> Result<()> {
    let info = parse_info(manifest_path)?;
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&info)?)?;
        return Ok(());
    }
    writeln!(out, "Path:     {}", info.path)?;
    writeln!(out, "Entries:  {}", info.entries)?;
    writeln!(out, "Unique:   {}", info.unique_paths)?;
    if !info.headers.is_empty() {
        writeln!(out, "\nHeaders:")?;
        let mut kvs: Vec<_> = info.headers.iter().collect();
        kvs.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in kvs {
            writeln!(out, "  {k:<16} {v}")?;
        }
    }
    if !info.algorithms.is_empty() {
        writeln!(out, "\nAlgorithms:")?;
        let mut algos: Vec<_> = info.algorithms.iter().collect();
        algos.sort_by_key(|(k, _)| k.as_str());
        for (algo, count) in algos {
            writeln!(out, "  {algo:<12} {count}")?;
        }
    }
    Ok(())
}
```

**Step 4: Confirm GREEN**

```bash
cargo test --all-features --test info_tests 2>&1 | tail -10
```

**Step 5: Commit**

```bash
git add tests/info_tests.rs
git commit -m "test(RED): add failing tests for blazehash info"

git add src/commands/info.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash info — display manifest metadata and header summary"
```

---

### Task 4: `blazehash missing` — find manifest entries not on disk

**Files:**
- Create: `tests/missing_tests.rs`
- Create: `src/commands/missing.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`

**What it does:** For each path in the manifest, checks if the file exists on disk. Reports missing paths to stdout. Exits 1 if any are missing. Supports `--root <dir>` to resolve relative paths against a base directory.

Flag name: `missing_root: Option<PathBuf>` → `--root`

**Step 1: Write the failing tests (RED)**

```rust
// tests/missing_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir, paths_exist: &[&str], paths_missing: &[&str]) -> std::path::PathBuf {
    let manifest = dir.path().join("test.hash");
    let mut content = String::new();
    for p in paths_exist.iter().chain(paths_missing.iter()) {
        content.push_str(&format!("blake3  {:064x}  {p}\n", 1u64));
    }
    fs::write(&manifest, &content).unwrap();
    manifest
}

#[test]
fn test_missing_exits_zero_when_all_present() {
    let dir = TempDir::new().unwrap();
    let f1 = dir.path().join("a.txt");
    let f2 = dir.path().join("b.txt");
    fs::write(&f1, b"a").unwrap();
    fs::write(&f2, b"b").unwrap();
    let manifest = write_manifest(&dir, &[f1.to_str().unwrap(), f2.to_str().unwrap()], &[]);
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["missing", manifest.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn test_missing_exits_nonzero_when_file_absent() {
    let dir = TempDir::new().unwrap();
    let f1 = dir.path().join("present.txt");
    fs::write(&f1, b"x").unwrap();
    let manifest = write_manifest(
        &dir,
        &[f1.to_str().unwrap()],
        &["/nonexistent/ghost.txt"],
    );
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["missing", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "should exit 1 when files missing");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ghost.txt"), "should report the missing file");
}

#[test]
fn test_missing_relative_paths_resolved_with_root() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("data.txt");
    fs::write(&f, b"content").unwrap();

    // manifest uses relative path
    let manifest = dir.path().join("rel.hash");
    fs::write(&manifest, "blake3  0000000000000000000000000000000000000000000000000000000000000000  data.txt\n").unwrap();

    // Without --root, data.txt doesn't exist relative to cwd
    // With --root <dir>, it does
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["missing", manifest.to_str().unwrap(), "--root", dir.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn test_missing_reports_count() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir, &[], &["/no/a.txt", "/no/b.txt", "/no/c.txt"]);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["missing", manifest.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let missing_lines: Vec<_> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(missing_lines.len(), 3, "should list all 3 missing files");
}

#[test]
fn test_missing_missing_manifest_fails() {
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["missing", "/no/such.hash"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test missing_tests 2>&1 | tail -10
```

**Step 3: Implement**

```rust
// src/commands/missing.rs
use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn find_missing(
    manifest_path: &Path,
    root: Option<&Path>,
    out: &mut impl Write,
) -> Result<usize> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut missing_count = 0usize;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue;
        }
        let path_str = parts[2].trim();
        let file_path = if let Some(r) = root {
            r.join(path_str)
        } else {
            Path::new(path_str).to_path_buf()
        };

        if !file_path.exists() {
            writeln!(out, "{path_str}")?;
            missing_count += 1;
        }
    }

    Ok(missing_count)
}
```

Add `missing_root: Option<std::path::PathBuf>` with `#[arg(long = "root")]` to `Cli`.
Add `Missing` to `Mode` enum and dispatch.

**Step 4: Confirm GREEN**

```bash
cargo test --all-features --test missing_tests 2>&1 | tail -10
```

**Step 5: Commit**

```bash
git add tests/missing_tests.rs
git commit -m "test(RED): add failing tests for blazehash missing"

git add src/commands/missing.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash missing — report manifest entries not present on disk"
```

---

### Task 5: `blazehash tag` — add/update/remove manifest header metadata

**Files:**
- Create: `tests/tag_tests.rs`
- Create: `src/commands/tag.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`

**What it does:** Reads a manifest, applies `--set key=value` (adds or replaces `## key: value` header) and `--unset key` (removes header), writes to stdout or `-o`. In-place editing requires `-o` pointing to the same file — keep it simple, always write to output.

Flags:
- `tag_set: Vec<String>` → `#[arg(long = "set")]` (repeatable)
- `tag_unset: Vec<String>` → `#[arg(long = "unset")]` (repeatable)

**Step 1: Write the failing tests (RED)**

```rust
// tests/tag_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("m.hash");
    fs::write(&p, "## case-id: OLD\n## examiner: Alice\nblake3  aaaa  file.txt\n").unwrap();
    p
}

#[test]
fn test_tag_set_adds_new_header() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tag", m.to_str().unwrap(), "--set", "reviewed-by=Bob"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## reviewed-by: Bob"), "new header should appear");
}

#[test]
fn test_tag_set_updates_existing_header() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tag", m.to_str().unwrap(), "--set", "case-id=NEW-999"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## case-id: NEW-999"), "header should be updated");
    assert!(!s.contains("OLD"), "old value should be gone");
}

#[test]
fn test_tag_unset_removes_header() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tag", m.to_str().unwrap(), "--unset", "examiner"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(!s.contains("examiner"), "unset header should be removed");
}

#[test]
fn test_tag_preserves_data_entries() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out = Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tag", m.to_str().unwrap(), "--set", "foo=bar"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("blake3  aaaa  file.txt"), "data entries must be preserved");
}

#[test]
fn test_tag_output_to_file() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir);
    let out_file = dir.path().join("tagged.hash");
    Command::cargo_bin("blazehash")
        .unwrap()
        .args(["tag", m.to_str().unwrap(), "--set", "status=reviewed", "-o", out_file.to_str().unwrap()])
        .assert()
        .success();
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("## status: reviewed"));
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test tag_tests 2>&1 | tail -10
```

**Step 3: Implement**

```rust
// src/commands/tag.rs
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

pub fn tag_manifest(
    manifest_path: &Path,
    set_pairs: &[String],
    unset_keys: &[String],
    out: &mut impl Write,
) -> Result<()> {
    // Parse --set key=value pairs
    let mut updates: HashMap<String, String> = HashMap::new();
    for pair in set_pairs {
        let (k, v) = pair.split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--set requires key=value format, got: {pair}"))?;
        updates.insert(k.trim().to_string(), v.trim().to_string());
    }
    let remove: std::collections::HashSet<String> = unset_keys.iter()
        .map(|k| k.trim().to_string())
        .collect();

    let content = std::fs::read_to_string(manifest_path)?;
    let mut seen_keys: std::collections::HashSet<String> = Default::default();

    // First pass: write existing headers (updated/filtered)
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("##") {
            let rest = rest.trim();
            if let Some((k, _)) = rest.split_once(':') {
                let key = k.trim().to_string();
                if remove.contains(&key) {
                    continue; // drop it
                }
                if let Some(new_val) = updates.get(&key) {
                    writeln!(out, "## {key}: {new_val}")?;
                    seen_keys.insert(key);
                    continue;
                }
                seen_keys.insert(key);
            }
            writeln!(out, "{line}")?;
        }
    }

    // Write new headers that weren't already present
    let mut new_keys: Vec<_> = updates.keys()
        .filter(|k| !seen_keys.contains(*k) && !remove.contains(*k))
        .collect();
    new_keys.sort();
    for k in new_keys {
        writeln!(out, "## {k}: {}", updates[k])?;
    }

    // Second pass: write data lines
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        writeln!(out, "{line}")?;
    }

    Ok(())
}
```

**Step 4: Confirm GREEN**

```bash
cargo test --all-features --test tag_tests 2>&1 | tail -10
```

**Step 5: Commit**

```bash
git add tests/tag_tests.rs
git commit -m "test(RED): add failing tests for blazehash tag"

git add src/commands/tag.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash tag — add/update/remove manifest header metadata"
```

---

### Task 6: Final integration check + push

**Step 1: Run full test suite**

```bash
cargo test --all-features 2>&1 | grep -E "^test result|FAILED"
```
Expected: all test results `ok`, no FAILED lines.

**Step 2: Run clippy**

```bash
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -20
```
Expected: no output (zero errors).

**Step 3: Push**

```bash
git push
```
