# blazehash Feature Batch 10 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Five manifest pipeline utilities that make blazehash composable with shell scripts and other tools.

**Architecture:** Same Mode dispatch pattern. Two commits per task: RED then GREEN. `cargo clippy --all-features -- -D warnings` must produce zero errors before the GREEN commit is made.

**Tech Stack:** Rust std only — no new dependencies.

---

### Task 1: `blazehash count` — print integer entry count

**Files:**
- Create: `tests/count_tests.rs`
- Create: `src/commands/count.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`

**What it does:** Reads a manifest and prints the number of data entries as a plain integer on stdout. No headers, no labels — just the number. Useful in scripts: `n=$(blazehash count case.hash)`.

**Step 1: Write failing tests (RED)**

```rust
// tests/count_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir, n: usize) -> std::path::PathBuf {
    let p = dir.path().join("test.hash");
    let mut content = String::from("## algorithm: blake3\n");
    for i in 1..=n {
        content.push_str(&format!("blake3  {:064x}  file{i}.txt\n", i));
    }
    fs::write(&p, &content).unwrap();
    p
}

#[test]
fn test_count_returns_correct_number() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 7);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["count", m.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out).trim().to_string();
    assert_eq!(s, "7");
}

#[test]
fn test_count_ignores_header_lines() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("with_headers.hash");
    fs::write(&p, "## case-id: X\n## examiner: Y\nblake3  aaaa  a.txt\nblake3  bbbb  b.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["count", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    assert_eq!(String::from_utf8_lossy(&out).trim(), "2");
}

#[test]
fn test_count_empty_manifest_returns_zero() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("empty.hash");
    fs::write(&p, "## algorithm: blake3\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["count", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    assert_eq!(String::from_utf8_lossy(&out).trim(), "0");
}

#[test]
fn test_count_missing_manifest_fails() {
    Command::cargo_bin("blazehash").unwrap()
        .args(["count", "/no/such.hash"])
        .assert().failure();
}
```

**Step 2: Confirm RED**
```bash
cargo test --all-features --test count_tests 2>&1 | tail -10
```

**Step 3: Implement**

```rust
// src/commands/count.rs
use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn count_entries(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;
    let n = content.lines().filter(|l| {
        let t = l.trim();
        !t.is_empty() && !t.starts_with('#') && !t.starts_with('%')
    }).count();
    writeln!(out, "{n}")?;
    Ok(())
}
```

Dispatch in `main.rs`:
```rust
if let Mode::Count = cli.mode() {
    let manifest_path = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("count: missing manifest path"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    commands::count::count_entries(manifest_path, &mut out)?;
    return Ok(());
}
```

**Step 4: Confirm GREEN + clippy**
```bash
cargo test --all-features --test count_tests 2>&1 | tail -10
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -5
```
Both must be zero errors before committing.

**Step 5: Commit**
```bash
git add tests/count_tests.rs
git commit -m "test(RED): add failing tests for blazehash count"

git add src/commands/count.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash count — print manifest entry count as integer"
```

---

### Task 2: `blazehash cat` — concatenate multiple manifests

**Files:**
- Create: `tests/cat_tests.rs`
- Create: `src/commands/cat.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`

**What it does:** Concatenates two or more manifests. Headers from the first manifest are emitted, then data entries from all manifests. Usage: `blazehash cat a.hash b.hash c.hash`.

Takes paths from `cli.paths[1..]` (all after the "cat" subcommand name).

**Step 1: Write failing tests (RED)**

```rust
// tests/cat_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn write_manifest(dir: &TempDir, name: &str, header: &str, entries: &[(&str, &str)]) -> std::path::PathBuf {
    let p = dir.path().join(name);
    let mut content = format!("{header}\n");
    for (hash, path) in entries {
        content.push_str(&format!("blake3  {hash}  {path}\n"));
    }
    fs::write(&p, &content).unwrap();
    p
}

#[test]
fn test_cat_combines_entries_from_both() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest(&dir, "a.hash", "## case-id: A", &[("aaaa", "a.txt")]);
    let b = write_manifest(&dir, "b.hash", "## case-id: B", &[("bbbb", "b.txt")]);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["cat", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("a.txt"), "should contain entries from first manifest");
    assert!(s.contains("b.txt"), "should contain entries from second manifest");
}

#[test]
fn test_cat_headers_from_first_only() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest(&dir, "a.hash", "## case-id: FIRST", &[("aaaa", "a.txt")]);
    let b = write_manifest(&dir, "b.hash", "## case-id: SECOND", &[("bbbb", "b.txt")]);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["cat", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("FIRST"), "headers from first manifest should appear");
    assert!(!s.contains("SECOND"), "headers from second manifest should NOT appear");
}

#[test]
fn test_cat_output_to_file() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest(&dir, "a.hash", "## x: 1", &[("aaaa", "a.txt")]);
    let b = write_manifest(&dir, "b.hash", "## x: 2", &[("bbbb", "b.txt")]);
    let out_file = dir.path().join("merged.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["cat", a.to_str().unwrap(), b.to_str().unwrap(),
               "-o", out_file.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("a.txt") && content.contains("b.txt"));
}

#[test]
fn test_cat_requires_at_least_two_inputs() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest(&dir, "a.hash", "## x: 1", &[("aaaa", "a.txt")]);
    Command::cargo_bin("blazehash").unwrap()
        .args(["cat", a.to_str().unwrap()])
        .assert().failure();
}

#[test]
fn test_cat_three_manifests() {
    let dir = TempDir::new().unwrap();
    let a = write_manifest(&dir, "a.hash", "## h: 1", &[("aaaa", "a.txt")]);
    let b = write_manifest(&dir, "b.hash", "## h: 2", &[("bbbb", "b.txt")]);
    let c = write_manifest(&dir, "c.hash", "## h: 3", &[("cccc", "c.txt")]);
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["cat", a.to_str().unwrap(), b.to_str().unwrap(), c.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("a.txt") && s.contains("b.txt") && s.contains("c.txt"));
}
```

**Step 2: Confirm RED**
```bash
cargo test --all-features --test cat_tests 2>&1 | tail -10
```

**Step 3: Implement**

```rust
// src/commands/cat.rs
use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn cat_manifests(paths: &[&Path], out: &mut impl Write) -> Result<()> {
    if paths.len() < 2 {
        anyhow::bail!("cat: requires at least two manifest paths");
    }

    // Emit headers from first manifest
    let first = std::fs::read_to_string(paths[0])?;
    for line in first.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.starts_with('%') {
            writeln!(out, "{line}")?;
        }
    }

    // Emit data entries from all manifests
    for path in paths {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let t = line.trim();
            if !t.is_empty() && !t.starts_with('#') && !t.starts_with('%') {
                writeln!(out, "{line}")?;
            }
        }
    }

    Ok(())
}
```

Dispatch in `main.rs` (note: paths are `cli.paths[1..]`):
```rust
if let Mode::Cat = cli.mode() {
    let input_paths: Vec<&std::path::Path> = cli.paths[1..].iter()
        .map(|p| p.as_path())
        .collect();
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    commands::cat::cat_manifests(&input_paths, &mut out)?;
    return Ok(());
}
```

**Step 4: Confirm GREEN + clippy**
```bash
cargo test --all-features --test cat_tests 2>&1 | tail -10
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -5
```

**Step 5: Commit**
```bash
git add tests/cat_tests.rs
git commit -m "test(RED): add failing tests for blazehash cat"

git add src/commands/cat.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash cat — concatenate manifests (headers from first, entries from all)"
```

---

### Task 3: `blazehash split` — split manifest into N-entry chunks

**Files:**
- Create: `tests/split_tests.rs`
- Create: `src/commands/split.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`

**What it does:** Splits a manifest into multiple output files of at most `--chunk N` entries each. Output files are named `<stem>_001.hash`, `<stem>_002.hash`, etc. The `--chunk` flag defaults to 1000. Each chunk file gets all headers from the source.

**New CLI field:** `split_chunk: usize` with `#[arg(long = "chunk", default_value = "1000")]`.

**Step 1: Write failing tests (RED)**

```rust
// tests/split_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn make_manifest(dir: &TempDir, n: usize) -> std::path::PathBuf {
    let p = dir.path().join("big.hash");
    let mut content = String::from("## algorithm: blake3\n");
    for i in 1..=n {
        content.push_str(&format!("blake3  {:064x}  file{i:04}.txt\n", i));
    }
    fs::write(&p, &content).unwrap();
    p
}

#[test]
fn test_split_creates_multiple_files() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 25);
    let out_dir = dir.path().join("out");
    fs::create_dir(&out_dir).unwrap();
    let out_base = out_dir.join("chunk");
    Command::cargo_bin("blazehash").unwrap()
        .args(["split", m.to_str().unwrap(),
               "--chunk", "10",
               "-o", out_base.to_str().unwrap()])
        .assert().success();
    assert!(out_dir.join("chunk_001.hash").exists(), "chunk 1 should exist");
    assert!(out_dir.join("chunk_002.hash").exists(), "chunk 2 should exist");
    assert!(out_dir.join("chunk_003.hash").exists(), "chunk 3 should exist");
}

#[test]
fn test_split_correct_entry_counts() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 25);
    let out_dir = dir.path().join("out");
    fs::create_dir(&out_dir).unwrap();
    let out_base = out_dir.join("part");
    Command::cargo_bin("blazehash").unwrap()
        .args(["split", m.to_str().unwrap(),
               "--chunk", "10",
               "-o", out_base.to_str().unwrap()])
        .assert().success();

    let count_entries = |path: &std::path::Path| -> usize {
        fs::read_to_string(path).unwrap().lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#') && !l.trim().starts_with('%'))
            .count()
    };

    assert_eq!(count_entries(&out_dir.join("part_001.hash")), 10);
    assert_eq!(count_entries(&out_dir.join("part_002.hash")), 10);
    assert_eq!(count_entries(&out_dir.join("part_003.hash")), 5);
}

#[test]
fn test_split_chunks_preserve_headers() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 5);
    let out_dir = dir.path().join("out");
    fs::create_dir(&out_dir).unwrap();
    let out_base = out_dir.join("chunk");
    Command::cargo_bin("blazehash").unwrap()
        .args(["split", m.to_str().unwrap(),
               "--chunk", "3",
               "-o", out_base.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(out_dir.join("chunk_001.hash")).unwrap();
    assert!(content.contains("## algorithm: blake3"), "headers should be in each chunk");
}

#[test]
fn test_split_single_chunk_when_entries_fit() {
    let dir = TempDir::new().unwrap();
    let m = make_manifest(&dir, 5);
    let out_dir = dir.path().join("out");
    fs::create_dir(&out_dir).unwrap();
    let out_base = out_dir.join("chunk");
    Command::cargo_bin("blazehash").unwrap()
        .args(["split", m.to_str().unwrap(),
               "--chunk", "100",
               "-o", out_base.to_str().unwrap()])
        .assert().success();
    assert!(out_dir.join("chunk_001.hash").exists());
    assert!(!out_dir.join("chunk_002.hash").exists(), "only one chunk needed");
}
```

**Step 2: Confirm RED**
```bash
cargo test --all-features --test split_tests 2>&1 | tail -10
```

**Step 3: Implement**

```rust
// src/commands/split.rs
use anyhow::Result;
use std::path::Path;

pub fn split_manifest(manifest_path: &Path, chunk_size: usize, out_base: &Path) -> Result<usize> {
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

    let stem = out_base.to_string_lossy();
    let mut chunk_num = 0usize;
    for chunk in entries.chunks(chunk_size) {
        chunk_num += 1;
        let filename = format!("{stem}_{chunk_num:03}.hash");
        let mut buf = String::new();
        for h in &headers {
            buf.push_str(h);
            buf.push('\n');
        }
        for e in chunk {
            buf.push_str(e);
            buf.push('\n');
        }
        std::fs::write(&filename, &buf)?;
    }

    Ok(chunk_num)
}
```

Dispatch in `main.rs`:
```rust
if let Mode::Split = cli.mode() {
    let manifest_path = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("split: missing manifest path"))?;
    let out_base = cli.output.as_deref()
        .ok_or_else(|| anyhow::anyhow!("split: -o <base> is required"))?;
    commands::split::split_manifest(manifest_path, cli.split_chunk, out_base)?;
    return Ok(());
}
```

**Step 4: Confirm GREEN + clippy**
```bash
cargo test --all-features --test split_tests 2>&1 | tail -10
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -5
```

**Step 5: Commit**
```bash
git add tests/split_tests.rs
git commit -m "test(RED): add failing tests for blazehash split"

git add src/commands/split.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash split — split manifest into N-entry chunks"
```

---

### Task 4: `blazehash uniq` — remove duplicate path entries

**Files:**
- Create: `tests/uniq_tests.rs`
- Create: `src/commands/uniq.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`

**What it does:** Removes entries with duplicate paths, keeping the **last** occurrence (so the most recent hash wins after a sort+uniq pipeline). Headers are preserved. Like POSIX `uniq` but path-aware and not requiring sorted input.

**Step 1: Write failing tests (RED)**

```rust
// tests/uniq_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_uniq_removes_duplicate_paths() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  file.txt\nblake3  bbbb  file.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["uniq", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let data: Vec<_> = s.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 1, "duplicate path should be collapsed to one entry");
}

#[test]
fn test_uniq_keeps_last_occurrence() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  first_hash_0000000000000000000000000000000000000000000000000000000000  file.txt\nblake3  last_hash_00000000000000000000000000000000000000000000000000000000000000  file.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["uniq", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("last_hash"), "should keep the last occurrence");
    assert!(!s.contains("first_hash"), "should discard the first occurrence");
}

#[test]
fn test_uniq_preserves_unique_entries() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  a.txt\nblake3  bbbb  b.txt\nblake3  cccc  c.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["uniq", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let data: Vec<_> = s.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 3, "all unique entries should be preserved");
}

#[test]
fn test_uniq_preserves_headers() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "## case-id: X\nblake3  aaaa  a.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["uniq", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("## case-id: X"), "headers must be preserved");
}

#[test]
fn test_uniq_output_to_file() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  dup.txt\nblake3  bbbb  dup.txt\n").unwrap();
    let out_file = dir.path().join("out.hash");
    Command::cargo_bin("blazehash").unwrap()
        .args(["uniq", p.to_str().unwrap(), "-o", out_file.to_str().unwrap()])
        .assert().success();
    let content = fs::read_to_string(&out_file).unwrap();
    let data: Vec<_> = content.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect();
    assert_eq!(data.len(), 1);
}
```

**Step 2: Confirm RED**
```bash
cargo test --all-features --test uniq_tests 2>&1 | tail -10
```

**Step 3: Implement**

```rust
// src/commands/uniq.rs
use anyhow::Result;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

pub fn uniq_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    let content = std::fs::read_to_string(manifest_path)?;

    let mut headers: Vec<&str> = Vec::new();
    // Use IndexMap-style insertion-order HashMap: process all lines, last write wins
    let mut order: Vec<String> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new(); // path -> index in order

    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() { continue; }
        if t.starts_with('#') || t.starts_with('%') {
            headers.push(line);
            continue;
        }
        let parts: Vec<&str> = t.splitn(3, "  ").collect();
        let path_key = if parts.len() == 3 {
            parts[2].trim().to_string()
        } else {
            line.to_string()
        };

        if let Some(&idx) = seen.get(&path_key) {
            order[idx] = line.to_string(); // overwrite with last occurrence
        } else {
            seen.insert(path_key, order.len());
            order.push(line.to_string());
        }
    }

    for h in &headers {
        writeln!(out, "{h}")?;
    }
    for entry in &order {
        writeln!(out, "{entry}")?;
    }

    Ok(())
}
```

**Step 4: Confirm GREEN + clippy**
```bash
cargo test --all-features --test uniq_tests 2>&1 | tail -10
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -5
```

**Step 5: Commit**
```bash
git add tests/uniq_tests.rs
git commit -m "test(RED): add failing tests for blazehash uniq"

git add src/commands/uniq.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash uniq — deduplicate manifest entries by path (keep last)"
```

---

### Task 5: `blazehash checksum` — hash the manifest file itself

**Files:**
- Create: `tests/checksum_tests.rs`
- Create: `src/commands/checksum.rs`
- Modify: `src/commands/mod.rs`, `src/cli.rs`, `src/main.rs`

**What it does:** Computes a BLAKE3 hash of the manifest file itself and prints it. Chain-of-custody for the manifest: proves the manifest hasn't been tampered with since it was generated. Output format: `blake3  <hash>  <path>`. Supports `--json`.

**Step 1: Write failing tests (RED)**

```rust
// tests/checksum_tests.rs
use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_checksum_outputs_hash_and_path() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("case.hash");
    fs::write(&p, "blake3  aaaa  file.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["checksum", p.to_str().unwrap()])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("blake3"), "should include algorithm");
    assert!(s.contains("case.hash"), "should include manifest filename");
}

#[test]
fn test_checksum_is_deterministic() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  file.txt\n").unwrap();
    let run1 = Command::cargo_bin("blazehash").unwrap()
        .args(["checksum", p.to_str().unwrap()])
        .output().unwrap().stdout;
    let run2 = Command::cargo_bin("blazehash").unwrap()
        .args(["checksum", p.to_str().unwrap()])
        .output().unwrap().stdout;
    assert_eq!(run1, run2, "checksum must be deterministic");
}

#[test]
fn test_checksum_changes_when_file_changes() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  file.txt\n").unwrap();
    let hash1 = Command::cargo_bin("blazehash").unwrap()
        .args(["checksum", p.to_str().unwrap()])
        .output().unwrap().stdout;
    fs::write(&p, "blake3  bbbb  file.txt\n").unwrap();
    let hash2 = Command::cargo_bin("blazehash").unwrap()
        .args(["checksum", p.to_str().unwrap()])
        .output().unwrap().stdout;
    assert_ne!(hash1, hash2, "different content must produce different checksum");
}

#[test]
fn test_checksum_json_output() {
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("m.hash");
    fs::write(&p, "blake3  aaaa  file.txt\n").unwrap();
    let out = Command::cargo_bin("blazehash").unwrap()
        .args(["checksum", p.to_str().unwrap(), "--json"])
        .assert().success().get_output().stdout.clone();
    let s = String::from_utf8_lossy(&out);
    let v: serde_json::Value = serde_json::from_str(&s).expect("should be valid JSON");
    assert!(v["hash"].as_str().is_some(), "JSON should have 'hash' field");
    assert!(v["path"].as_str().is_some(), "JSON should have 'path' field");
}

#[test]
fn test_checksum_missing_file_fails() {
    Command::cargo_bin("blazehash").unwrap()
        .args(["checksum", "/no/such.hash"])
        .assert().failure();
}
```

**Step 2: Confirm RED**
```bash
cargo test --all-features --test checksum_tests 2>&1 | tail -10
```

**Step 3: Implement**

```rust
// src/commands/checksum.rs
use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn checksum_manifest(manifest_path: &Path, json: bool, out: &mut impl Write) -> Result<()> {
    let bytes = std::fs::read(manifest_path)?;
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let path_str = manifest_path.display().to_string();

    if json {
        writeln!(out, "{}", serde_json::json!({
            "algorithm": "blake3",
            "hash": hash,
            "path": path_str,
        }))?;
    } else {
        writeln!(out, "blake3  {hash}  {path_str}")?;
    }

    Ok(())
}
```

`blake3` is already a dependency. `serde_json` is already a dependency.

**Step 4: Confirm GREEN + clippy**
```bash
cargo test --all-features --test checksum_tests 2>&1 | tail -10
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -5
```

**Step 5: Commit**
```bash
git add tests/checksum_tests.rs
git commit -m "test(RED): add failing tests for blazehash checksum"

git add src/commands/checksum.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash checksum — hash the manifest file itself (chain of custody)"
```

---

### Task 6: Final integration check + push

```bash
cargo test --all-features 2>&1 | grep -E "^test result|FAILED"
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -10
git push
```

All test results must be `ok`. Zero clippy errors. Then push.
