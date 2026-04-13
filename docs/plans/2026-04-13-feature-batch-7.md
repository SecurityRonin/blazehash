# Feature Batch 7 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Five manifest-intelligence features focused on interoperability, validation, and search — the analyst daily-driver commands.

**Architecture:**
- All five are pure manifest transformations (read content, emit content) — no new dependencies
- `convert` adds read-side parsers for md5sum/sha256sum/hashdeep/sfv formats
- `lint` is a pure read + report pass over a manifest
- `head` and `search` are stateless stream filters
- `export` is a write-side formatter (CSV/JSONL/TSV)
- All wired through the existing `cli.rs` / `main.rs` dispatch pattern; each command is a new `Mode` variant

**Tech Stack:** Rust, `std::io`, existing `manifest_loader.rs` patterns, `csv` (already a dev-dep or standard stdlib), `serde_json` (already in tree)

---

### Task 1: `blazehash convert` — import md5sum / sha256sum / hashdeep manifests

Convert legacy hash files into the blazehash two-space manifest format so forensic workflows that start with system tools (`sha256sum`, `md5sum`, hashdeep) can be imported.

**Files:**
- Create: `src/commands/convert.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/cli.rs` (add `Convert` mode, `--from` flag)
- Modify: `src/main.rs`
- Create: `tests/convert_tests.rs`

**Formats to support:**

| Tool | Line format | Auto-detect signal |
|------|-------------|-------------------|
| `sha256sum` | `<hash>  <path>` or `<hash> *<path>` | 64-hex + two-space or asterisk |
| `md5sum` | `<hash>  <path>` or `<hash> *<path>` | 32-hex + two-space or asterisk |
| `sha1sum` | `<hash>  <path>` or `<hash> *<path>` | 40-hex + two-space |
| hashdeep | `%%%% HASHDEEP-1.0` header, `## hashdeep…`, then `md5,sha256,filename` CSV | header present |
| sfv | `; comment`, `<path> <hash>` (reversed order!) | `;` comment lines |

**Step 1: Write failing tests**

```rust
// tests/convert_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_convert_sha256sum_format() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("sums.txt");
    fs::write(&input, concat!(
        "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd  docs/a.pdf\n",
        "1122334411223344112233441122334411223344112233441122334411223344 *images/b.jpg\n",
    )).unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "sha256sum"])
        .output().unwrap();
    assert!(out.status.success(), "convert failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Output should use blazehash format: algo  hash  path
    assert!(stdout.contains("sha256"), "output must declare sha256 algo");
    assert!(stdout.contains("docs/a.pdf"), "path must be present");
    assert!(stdout.contains("images/b.jpg"), "binary-mode asterisk path must be stripped");
}

#[test]
fn test_convert_md5sum_format() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("md5s.txt");
    fs::write(&input, "aabbccddaabbccddaabbccddaabbccdd  file.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "md5sum"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("md5"), "output must declare md5 algo");
    assert!(stdout.contains("file.txt"));
}

#[test]
fn test_convert_hashdeep_format() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("hashdeep.txt");
    fs::write(&input, concat!(
        "%%%% HASHDEEP-1.0\n",
        "%%%% size,md5,sha256,filename\n",
        "## Invoked from: /evidence\n",
        "## $ hashdeep -r /evidence\n",
        "## \n",
        "1024,aabbccddaabbccddaabbccddaabbccdd,",
        "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd,",
        "/evidence/file.bin\n",
    )).unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "hashdeep"])
        .output().unwrap();
    assert!(out.status.success(), "convert hashdeep failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sha256") || stdout.contains("md5"), "must have algo");
    assert!(stdout.contains("file.bin"), "path must appear");
}

#[test]
fn test_convert_sfv_format() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("sums.sfv");
    fs::write(&input, concat!(
        "; SFV created by WinCRC32\n",
        "movie.mkv DEADBEEF\n",
        "subs.srt  CAFEBABE\n",
    )).unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "sfv"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("crc32") || stdout.contains("CRC"), "sfv is CRC32");
    assert!(stdout.contains("movie.mkv"));
}

#[test]
fn test_convert_output_to_file() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("sums.txt");
    fs::write(&input, "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd  a.txt\n").unwrap();
    let out_path = dir.path().join("converted.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "sha256sum",
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("sha256"));
    assert!(content.contains("a.txt"));
}

#[test]
fn test_convert_unknown_format_fails() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("x.txt");
    fs::write(&input, "data\n").unwrap();
    Command::cargo_bin("blazehash").unwrap()
        .args(["convert", input.to_str().unwrap(), "--from", "foobar"])
        .assert().failure();
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test convert_tests 2>&1 | grep -E "error|FAILED|test result"
```

Expected: compile errors or subcommand-not-found failures.

**Step 3: Implement `src/commands/convert.rs`**

```rust
//! Convert legacy hash manifest formats (md5sum, sha256sum, hashdeep, sfv)
//! into the blazehash two-space format: `algo  hash  path`.

use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn convert_manifest(
    input_path: &Path,
    format: &str,
    out: &mut impl Write,
) -> Result<()> {
    let content = std::fs::read_to_string(input_path)?;
    writeln!(out, "## converted-from: {format}")?;
    match format.to_ascii_lowercase().as_str() {
        "sha256sum" => convert_sumfile(&content, "sha256", out),
        "sha1sum"   => convert_sumfile(&content, "sha1", out),
        "md5sum"    => convert_sumfile(&content, "md5", out),
        "hashdeep"  => convert_hashdeep(&content, out),
        "sfv"       => convert_sfv(&content, out),
        other       => bail!("unknown format '{other}'; supported: sha256sum, sha1sum, md5sum, hashdeep, sfv"),
    }
}

/// Parse `sha256sum`-style lines: `<hash>  <path>` or `<hash> *<path>`.
fn convert_sumfile(content: &str, algo: &str, out: &mut impl Write) -> Result<()> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split on first whitespace run
        if let Some((hash, rest)) = line.split_once(|c: char| c.is_ascii_whitespace()) {
            let path = rest.trim_start_matches(|c: char| c.is_ascii_whitespace())
                          .trim_start_matches('*'); // strip binary-mode marker
            let hash = hash.trim();
            if !path.is_empty() && !hash.is_empty() {
                writeln!(out, "{algo}  {hash}  {path}")?;
            }
        }
    }
    Ok(())
}

/// Parse hashdeep CSV format.
/// Header: `%%%% HASHDEEP-1.0` then `%%%% size,<algo1>,<algo2>,filename`
/// Data:   `<size>,<hash1>,<hash2>,<filename>`
fn convert_hashdeep(content: &str, out: &mut impl Write) -> Result<()> {
    let mut algos: Vec<String> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("%%%%") {
            // `%%%% size,md5,sha256,filename`
            if let Some(rest) = line.strip_prefix("%%%%") {
                let rest = rest.trim();
                if rest.starts_with("size,") || rest.contains(',') {
                    let fields: Vec<&str> = rest.split(',').collect();
                    // fields[0] = "size", fields[last] = "filename", middle = algos
                    for f in fields.iter().skip(1) {
                        if *f != "filename" {
                            algos.push(f.to_ascii_lowercase());
                        }
                    }
                }
            }
            continue;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if algos.is_empty() {
            continue;
        }
        // Data line: `size,hash1,hash2,...,filename`
        let parts: Vec<&str> = line.splitn(algos.len() + 2, ',').collect();
        if parts.len() < algos.len() + 2 {
            continue; // malformed
        }
        let filename = parts[algos.len() + 1];
        // Use last (strongest) algo by default, emit all
        for (i, algo) in algos.iter().enumerate() {
            let hash = parts[i + 1];
            writeln!(out, "{algo}  {hash}  {filename}")?;
        }
    }
    Ok(())
}

/// Parse SFV: `; comment` lines, `<filename> <CRC32>` (reversed from sumfile!).
fn convert_sfv(content: &str, out: &mut impl Write) -> Result<()> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        // SFV: `filename crc32_hex` — last token is hash, rest is filename
        if let Some((filename, hash)) = line.rsplit_once(|c: char| c.is_ascii_whitespace()) {
            let filename = filename.trim_end();
            let hash = hash.trim();
            if !filename.is_empty() && !hash.is_empty() {
                writeln!(out, "crc32  {hash}  {filename}")?;
            }
        }
    }
    Ok(())
}
```

**Step 4: Wire into CLI**

Add `Convert` to `Mode` enum in `src/cli.rs` and `--from` flag:

```rust
// in Cli struct
/// Source format for convert subcommand (sha256sum, md5sum, sha1sum, hashdeep, sfv)
#[arg(long = "from", value_name = "FORMAT")]
pub from_format: Option<String>,
```

Add `Convert` variant to `Mode`:
```rust
Convert,
```

Add detection in `mode()` method (after existing subcommand checks):
```rust
} else if self.paths.first().map(|p| p.as_os_str())
    == Some(std::ffi::OsStr::new("convert"))
{
    Mode::Convert
```

Add dispatch in `src/main.rs` (before the `Mode::Vt` block):
```rust
if let Mode::Convert = cli.mode() {
    let input = cli
        .paths
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash convert <file> --from <format> [-o output]"))?;
    let format = cli
        .from_format
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--from <format> is required (sha256sum, md5sum, sha1sum, hashdeep, sfv)"))?;
    if let Some(out_path) = &output {
        let mut f = std::fs::File::create(out_path)?;
        commands::convert::convert_manifest(&input, format, &mut f)?;
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        commands::convert::convert_manifest(&input, format, &mut handle)?;
    }
    return Ok(());
}
```

Add `Mode::Convert => unreachable!()` to the exhaustive match.
Add `pub mod convert;` to `src/commands/mod.rs`.

**Step 5: Run tests to confirm GREEN**

```bash
cargo test --all-features --test convert_tests 2>&1 | grep -E "FAILED|ok|test result"
```

Expected: `test result: ok. 6 passed; 0 failed`

**Step 6: Commit**

```bash
git add tests/convert_tests.rs
git commit -m "test(RED): add failing tests for blazehash convert"

git add src/commands/convert.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash convert — import md5sum/sha256sum/hashdeep/sfv manifests"
```

---

### Task 2: `blazehash lint` — validate manifest integrity

Report problems in a manifest: duplicate paths, duplicate hashes (possible hardlinks), malformed lines, unknown algorithms, missing fields.

**Files:**
- Create: `src/commands/lint.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Create: `tests/lint_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/lint_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_clean_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("clean.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/a.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  docs/b.pdf\n",
    )).unwrap();
    p
}

#[test]
fn test_lint_clean_manifest_exits_zero() {
    let dir = TempDir::new().unwrap();
    let manifest = write_clean_manifest(&dir);
    Command::cargo_bin("blazehash").unwrap()
        .args(["lint", manifest.to_str().unwrap()])
        .assert().success();
}

#[test]
fn test_lint_duplicate_path_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("dup.hash");
    fs::write(&p, concat!(
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/a.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  docs/a.pdf\n",  // same path!
    )).unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["lint", p.to_str().unwrap()])
        .output().unwrap();
    assert!(!out.status.success(), "duplicate path should cause lint failure");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("duplicate") || combined.contains("dup"),
        "should mention duplicate, got:\n{combined}");
}

#[test]
fn test_lint_duplicate_hash_warns() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("dup_hash.hash");
    fs::write(&p, concat!(
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/a.pdf\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/b.pdf\n",  // same hash!
    )).unwrap();
    // Duplicate hash is a warning (possible hardlink), not an error — exit 0 but warn
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["lint", p.to_str().unwrap()])
        .output().unwrap();
    // Exit 0 (warning only)
    assert!(out.status.success(), "duplicate hash is a warning, not error");
    let combined = format!("{}{}", 
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr));
    assert!(combined.to_lowercase().contains("warn") || combined.contains("duplicate hash") || combined.contains("hardlink"),
        "should warn about duplicate hash, got:\n{combined}");
}

#[test]
fn test_lint_malformed_line_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("malformed.hash");
    fs::write(&p, "this line has no double-space separator at all\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["lint", p.to_str().unwrap()])
        .output().unwrap();
    assert!(!out.status.success(), "malformed line should cause lint failure");
}

#[test]
fn test_lint_json_output() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("dup.hash");
    fs::write(&p, concat!(
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/a.pdf\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  docs/a.pdf\n",
    )).unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["lint", p.to_str().unwrap(), "--json"])
        .output().unwrap();
    // Even on failure, --json should produce valid JSON on stdout
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.trim().is_empty() {
        let json: serde_json::Value = serde_json::from_str(&stdout)
            .expect("--json must produce valid JSON even on failure");
        assert!(json["errors"].is_array() || json["warnings"].is_array(),
            "JSON should have errors or warnings array");
    }
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test lint_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/commands/lint.rs`**

```rust
//! Manifest linter: detect duplicate paths, duplicate hashes, malformed lines.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct LintReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl LintReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn lint_manifest(manifest_path: &Path) -> Result<LintReport> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut report = LintReport::default();

    let mut seen_paths: HashMap<String, usize> = HashMap::new();   // path → first line number
    let mut seen_hashes: HashMap<String, (usize, String)> = HashMap::new(); // hash → (line, path)
    let mut has_data_lines = false;

    for (i, line) in content.lines().enumerate() {
        let lineno = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            report.errors.push(format!(
                "line {lineno}: malformed entry (expected 'algo  hash  path'): {trimmed}"
            ));
            continue;
        }

        has_data_lines = true;
        let path = parts[2].trim().to_string();
        let hash = parts[1].trim().to_string();

        // Duplicate path check (error)
        if let Some(first) = seen_paths.insert(path.clone(), lineno) {
            report.errors.push(format!(
                "line {lineno}: duplicate path '{path}' (first seen at line {first})"
            ));
        }

        // Duplicate hash check (warning — possible hardlink)
        if let Some((first_line, first_path)) = seen_hashes.insert(hash.clone(), (lineno, path.clone())) {
            report.warnings.push(format!(
                "line {lineno}: duplicate hash '{hash}' for '{path}' (also on line {first_line} for '{first_path}') — possible hardlink"
            ));
        }
    }

    // Empty manifest is valid (just headers)
    let _ = has_data_lines;
    Ok(report)
}

pub fn print_report(report: &LintReport) {
    for e in &report.errors {
        eprintln!("ERROR: {e}");
    }
    for w in &report.warnings {
        eprintln!("WARN:  {w}");
    }
    if report.ok() && report.warnings.is_empty() {
        println!("OK");
    }
}
```

**Step 4: Wire into CLI**

Add `Lint` to `Mode` enum in `src/cli.rs`, detected when `paths[0] == "lint"`.

Add dispatch in `src/main.rs`:
```rust
if let Mode::Lint = cli.mode() {
    let manifest = cli
        .paths
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash lint <manifest>"))?;
    let report = commands::lint::lint_manifest(&manifest)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        commands::lint::print_report(&report);
    }
    if !report.ok() {
        std::process::exit(1);
    }
    return Ok(());
}
```

Add `Mode::Lint => unreachable!()` to exhaustive match.
Add `pub mod lint;` to `src/commands/mod.rs`.

**Step 5: Run tests to confirm GREEN**

```bash
cargo test --all-features --test lint_tests 2>&1 | grep -E "FAILED|ok|test result"
```

Expected: `test result: ok. 5 passed; 0 failed`

**Step 6: Commit**

```bash
git add tests/lint_tests.rs
git commit -m "test(RED): add failing tests for blazehash lint"

git add src/commands/lint.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash lint — manifest validation (duplicate paths/hashes, malformed lines)"
```

---

### Task 3: `blazehash head` — take first N entries from a manifest

Output only the first N hash entries from a manifest, preserving all header lines. Useful for quick inspection of large manifests and scripted sampling.

**Files:**
- Create: `src/commands/head.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Create: `tests/head_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/head_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  file1.txt\n",
        "sha256  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  file2.txt\n",
        "sha256  cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  file3.txt\n",
        "sha256  dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  file4.txt\n",
        "sha256  eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  file5.txt\n",
    )).unwrap();
    p
}

#[test]
fn test_head_default_10() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    // Default N=10: all 5 entries returned (manifest has only 5)
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["head", manifest.to_str().unwrap()])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // All 5 files should appear
    for i in 1..=5 {
        assert!(stdout.contains(&format!("file{i}.txt")), "file{i}.txt should be present");
    }
}

#[test]
fn test_head_n_limits_entries() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["head", manifest.to_str().unwrap(), "--count", "2"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("file1.txt"), "first entry must be present");
    assert!(stdout.contains("file2.txt"), "second entry must be present");
    assert!(!stdout.contains("file3.txt"), "third entry must be absent");
}

#[test]
fn test_head_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["head", manifest.to_str().unwrap(), "--count", "1"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## case: CASE-001"), "headers must be preserved");
}

#[test]
fn test_head_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("head.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["head", manifest.to_str().unwrap(), "--count", "3",
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    let data_lines: Vec<_> = content.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data_lines.len(), 3, "file should have exactly 3 data lines");
}

#[test]
fn test_head_count_zero_outputs_headers_only() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["head", manifest.to_str().unwrap(), "--count", "0"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data_lines: Vec<_> = stdout.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert!(data_lines.is_empty(), "count=0 must output no data entries");
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test head_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/commands/head.rs`**

```rust
//! Output first N entries from a manifest, preserving all header lines.

use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn head_manifest(manifest_path: &Path, count: usize, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut emitted = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        // Always pass through headers
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        // Data line — only emit if under quota
        if emitted < count {
            writeln!(out, "{line}")?;
            emitted += 1;
        }
        // Stop reading early once quota is filled
        if emitted >= count {
            break;
        }
    }
    Ok(())
}
```

**Step 4: Wire into CLI**

Add `--count` flag (default 10) to `Cli`:
```rust
/// Number of entries to output for head subcommand (default: 10)
#[arg(long = "count", short = 'n', default_value = "10")]
pub count: usize,
```

Add `Head` to `Mode` enum and detect `"head"` in `mode()`.

Add dispatch in `src/main.rs`:
```rust
if let Mode::Head = cli.mode() {
    let manifest = cli
        .paths
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash head <manifest> [--count N]"))?;
    if let Some(out_path) = &output {
        let mut f = std::fs::File::create(out_path)?;
        commands::head::head_manifest(&manifest, cli.count, &mut f)?;
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        commands::head::head_manifest(&manifest, cli.count, &mut handle)?;
    }
    return Ok(());
}
```

Add `pub mod head;` to `src/commands/mod.rs`.
Add `Mode::Head => unreachable!()` to exhaustive match.

**Step 5: Run tests to confirm GREEN**

```bash
cargo test --all-features --test head_tests 2>&1 | grep -E "FAILED|ok|test result"
```

Expected: `test result: ok. 5 passed; 0 failed`

**Step 6: Commit**

```bash
git add tests/head_tests.rs
git commit -m "test(RED): add failing tests for blazehash head"

git add src/commands/head.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash head — output first N entries from a manifest"
```

---

### Task 4: `blazehash search` — search manifest entries by hash prefix or path substring

Search a manifest for entries whose path or hash matches a pattern, outputting matching entries in manifest format (headers preserved). Enables quick lookup like `grep` but manifest-aware.

**Files:**
- Create: `src/commands/search.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Create: `tests/search_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/search_tests.rs
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
fn test_search_by_path_substring() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["search", manifest.to_str().unwrap(), "--path", "docs/"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("contract.pdf"), "docs/contract.pdf must match");
    assert!(stdout.contains("notes.txt"), "docs/notes.txt must match");
    assert!(!stdout.contains("photo.jpg"), "images/ must not match");
}

#[test]
fn test_search_by_hash_prefix() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    // Search for hash starting with "aaa"
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["search", manifest.to_str().unwrap(), "--hash", "aaa"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("contract.pdf"), "hash prefix 'aaa' must match contract.pdf");
    assert!(!stdout.contains("photo.jpg"), "hash 'bbb...' must not match");
}

#[test]
fn test_search_no_match_exits_nonzero_or_empty() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["search", manifest.to_str().unwrap(), "--path", "nonexistent"])
        .output().unwrap();
    // Either exit 1 (grep-style) or exit 0 with empty data lines
    let stdout = String::from_utf8_lossy(&out.stdout);
    let data_lines: Vec<_> = stdout.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    // No data lines expected
    assert!(data_lines.is_empty() || !out.status.success(),
        "no-match should produce empty output or nonzero exit");
}

#[test]
fn test_search_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["search", manifest.to_str().unwrap(), "--path", "docs/"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("## case: CASE-001"), "headers must be preserved");
}

#[test]
fn test_search_case_insensitive_flag() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["search", manifest.to_str().unwrap(), "--path", "README", "--ignore-case"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("README.md"), "case-insensitive match must find README.md");
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test search_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/commands/search.rs`**

```rust
//! Search manifest entries by path substring or hash prefix/substring.

use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub struct SearchOpts<'a> {
    pub path_query: Option<&'a str>,
    pub hash_query: Option<&'a str>,
    pub ignore_case: bool,
}

pub fn search_manifest(
    manifest_path: &Path,
    opts: &SearchOpts<'_>,
    out: &mut impl Write,
) -> Result<usize> {
    let content = std::fs::read_to_string(manifest_path)?;
    let mut matched = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }

        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            continue;
        }

        let hash = parts[1].trim();
        let path = parts[2].trim();

        let path_ok = match opts.path_query {
            None => true,
            Some(q) => {
                if opts.ignore_case {
                    path.to_ascii_lowercase().contains(&q.to_ascii_lowercase())
                } else {
                    path.contains(q)
                }
            }
        };

        let hash_ok = match opts.hash_query {
            None => true,
            Some(q) => {
                if opts.ignore_case {
                    hash.to_ascii_lowercase().starts_with(&q.to_ascii_lowercase())
                } else {
                    hash.starts_with(q)
                }
            }
        };

        if path_ok && hash_ok {
            writeln!(out, "{line}")?;
            matched += 1;
        }
    }

    Ok(matched)
}
```

**Step 4: Wire into CLI**

Add `--path` (path query), `--hash` (hash prefix), `--ignore-case` (`-i`) flags to `Cli`:
```rust
/// Path substring to search for (for search subcommand)
#[arg(long = "path", value_name = "QUERY")]
pub search_path: Option<String>,

/// Hash prefix to search for (for search subcommand)
#[arg(long = "hash", value_name = "PREFIX")]
pub search_hash: Option<String>,

/// Case-insensitive search
#[arg(long = "ignore-case", short = 'i')]
pub ignore_case: bool,
```

Add `Search` to `Mode` enum, detect `"search"` in `mode()`.

Add dispatch in `src/main.rs`:
```rust
if let Mode::Search = cli.mode() {
    let manifest = cli
        .paths
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash search <manifest> [--path QUERY] [--hash PREFIX]"))?;
    let opts = commands::search::SearchOpts {
        path_query: cli.search_path.as_deref(),
        hash_query: cli.search_hash.as_deref(),
        ignore_case: cli.ignore_case,
    };
    let matched = if let Some(out_path) = &output {
        let mut f = std::fs::File::create(out_path)?;
        commands::search::search_manifest(&manifest, &opts, &mut f)?
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        commands::search::search_manifest(&manifest, &opts, &mut handle)?
    };
    if matched == 0 {
        std::process::exit(1);
    }
    return Ok(());
}
```

Add `pub mod search;` to `src/commands/mod.rs`.
Add `Mode::Search => unreachable!()` to exhaustive match.

**Step 5: Run tests to confirm GREEN**

```bash
cargo test --all-features --test search_tests 2>&1 | grep -E "FAILED|ok|test result"
```

Expected: `test result: ok. 5 passed; 0 failed`

**Step 6: Commit**

```bash
git add tests/search_tests.rs
git commit -m "test(RED): add failing tests for blazehash search"

git add src/commands/search.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash search — search manifest entries by path substring or hash prefix"
```

---

### Task 5: `blazehash export` — export manifest to CSV / JSONL / TSV

Export a blazehash manifest to structured formats for ingestion by spreadsheets, Splunk, Pandas, DuckDB, etc.

**Files:**
- Create: `src/commands/export.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`
- Create: `tests/export_tests.rs`

**Step 1: Write failing tests**

```rust
// tests/export_tests.rs
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

fn write_manifest(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.path().join("case.hash");
    fs::write(&p, concat!(
        "## case: CASE-001\n",
        "sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  docs/contract.pdf\n",
        "blake3  bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  images/photo.jpg\n",
    )).unwrap();
    p
}

#[test]
fn test_export_csv_has_header_row() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--format", "csv"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first_line = stdout.lines().next().unwrap_or("");
    // Header must have algo, hash, path columns (case-insensitive)
    assert!(first_line.to_ascii_lowercase().contains("algo") ||
            first_line.to_ascii_lowercase().contains("algorithm"),
        "CSV first line must be a header with algo column, got: {first_line}");
}

#[test]
fn test_export_csv_has_data_rows() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--format", "csv"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("contract.pdf"), "CSV must contain path");
    assert!(stdout.contains("sha256"), "CSV must contain algo");
}

#[test]
fn test_export_jsonl_one_json_object_per_line() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--format", "jsonl"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Each non-empty line must be valid JSON
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let obj: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("JSONL line is not valid JSON: {line}\n{e}"));
        assert!(obj["path"].is_string(), "JSON line must have path field");
        assert!(obj["hash"].is_string(), "JSON line must have hash field");
        assert!(obj["algo"].is_string(), "JSON line must have algo field");
    }
}

#[test]
fn test_export_tsv_tab_separated() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--format", "tsv"])
        .output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Data rows should contain tab characters
    let has_tab = stdout.lines()
        .filter(|l| !l.trim().is_empty())
        .any(|l| l.contains('\t'));
    assert!(has_tab, "TSV output must contain tab characters");
}

#[test]
fn test_export_unknown_format_fails() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--format", "xls"])
        .assert().failure();
}

#[test]
fn test_export_output_to_file() {
    let dir = TempDir::new().unwrap();
    let manifest = write_manifest(&dir);
    let out_path = dir.path().join("out.csv");
    Command::cargo_bin("blazehash").unwrap()
        .args(["export", manifest.to_str().unwrap(), "--format", "csv",
               "-o", out_path.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("contract.pdf"));
}
```

**Step 2: Run to confirm RED**

```bash
cargo test --all-features --test export_tests 2>&1 | grep -E "error|FAILED|test result"
```

**Step 3: Implement `src/commands/export.rs`**

```rust
//! Export a blazehash manifest to structured formats: CSV, JSONL, TSV.

use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn export_manifest(manifest_path: &Path, format: &str, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    match format.to_ascii_lowercase().as_str() {
        "csv"  => export_delimited(&content, ',', true, out),
        "tsv"  => export_delimited(&content, '\t', true, out),
        "jsonl" => export_jsonl(&content, out),
        other  => bail!("unknown export format '{other}'; supported: csv, tsv, jsonl"),
    }
}

fn export_delimited(content: &str, sep: char, header: bool, out: &mut impl Write) -> Result<()> {
    if header {
        writeln!(out, "algo{sep}hash{sep}path")?;
    }
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            let algo = parts[0].trim();
            let hash = parts[1].trim();
            let path = parts[2].trim();
            // Quote path if it contains the separator
            let path_cell = if path.contains(sep) || path.contains('"') {
                format!("\"{}\"", path.replace('"', "\"\""))
            } else {
                path.to_string()
            };
            writeln!(out, "{algo}{sep}{hash}{sep}{path_cell}")?;
        }
    }
    Ok(())
}

fn export_jsonl(content: &str, out: &mut impl Write) -> Result<()> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            let obj = serde_json::json!({
                "algo": parts[0].trim(),
                "hash": parts[1].trim(),
                "path": parts[2].trim(),
            });
            writeln!(out, "{}", serde_json::to_string(&obj)?)?;
        }
    }
    Ok(())
}
```

**Step 4: Wire into CLI**

Add `--format` flag (reuse the existing `output_format` if it doesn't conflict, or add `export_format`):
```rust
/// Export format: csv, tsv, jsonl (for export subcommand)
#[arg(long = "format", value_name = "FORMAT")]
pub export_format: Option<String>,
```

Add `Export` to `Mode` enum, detect `"export"` in `mode()`.

Add dispatch in `src/main.rs`:
```rust
if let Mode::Export = cli.mode() {
    let manifest = cli
        .paths
        .get(1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash export <manifest> --format <csv|tsv|jsonl>"))?;
    let fmt = cli
        .export_format
        .as_deref()
        .unwrap_or("csv");
    if let Some(out_path) = &output {
        let mut f = std::fs::File::create(out_path)?;
        commands::export::export_manifest(&manifest, fmt, &mut f)?;
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        commands::export::export_manifest(&manifest, fmt, &mut handle)?;
    }
    return Ok(());
}
```

Add `pub mod export;` to `src/commands/mod.rs`.
Add `Mode::Export => unreachable!()` to exhaustive match.

**Step 5: Run tests to confirm GREEN**

```bash
cargo test --all-features --test export_tests 2>&1 | grep -E "FAILED|ok|test result"
```

Expected: `test result: ok. 6 passed; 0 failed`

**Step 6: Commit**

```bash
git add tests/export_tests.rs
git commit -m "test(RED): add failing tests for blazehash export"

git add src/commands/export.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash export — export manifest to CSV/JSONL/TSV"
```

---

### Task 6: Final integration check

**Step 1: Full test suite with all features**

```bash
cargo test --all-features 2>&1 | grep -E "^test result|FAILED"
```

Expected: all green, no failures.

**Step 2: Clippy**

```bash
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -20
```

Expected: no errors. Fix any that appear before committing.

**Step 3: Verify new subcommands appear in help**

```bash
cargo run --all-features -- --help 2>&1 | grep -E "convert|lint|head|search|export"
```

**Step 4: Push**

```bash
git push
```

---

## Summary

| Task | Subcommand | Purpose | Key file |
|------|-----------|---------|----------|
| 1 | `blazehash convert` | Import md5sum/sha256sum/hashdeep/sfv | `src/commands/convert.rs` |
| 2 | `blazehash lint` | Validate: dup paths, dup hashes, malformed | `src/commands/lint.rs` |
| 3 | `blazehash head` | First N entries from manifest | `src/commands/head.rs` |
| 4 | `blazehash search` | Search by path substring or hash prefix | `src/commands/search.rs` |
| 5 | `blazehash export` | Export to CSV/JSONL/TSV | `src/commands/export.rs` |
| 6 | Integration check | Full test suite + clippy + push | — |

All tasks are pure manifest transformations — no new Cargo dependencies required.
