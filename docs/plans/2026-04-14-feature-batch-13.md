# blazehash Feature Batch 13 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Five manifest analysis and quality commands — duplicates, repair, sym-diff, first, annotate.

**Architecture:** Standard Mode dispatch pattern (same as all previous batches).
Manifest data lines: `algo  hash  path` (two spaces). Headers: `##` or `%%`.
Two commits per task: RED (failing tests) then GREEN (implementation, passing + zero clippy).

---

## Task 1: `blazehash duplicates`

Find entries whose hash appears more than once — i.e. content-identical files.

**Behavior:**
- Reads a manifest (first positional path after "duplicates")
- Groups entries by hash value
- Emits entries for any hash that appears 2+ times (all occurrences, not just one)
- Output format: same as manifest data lines (`algo  hash  path`)
- Headers skipped in output
- Entries sorted by hash then path for deterministic output
- Supports `-o <file>`
- No new CLI fields needed
- Module: `duplicates`

**`src/commands/duplicates.rs`:**
```rust
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

pub fn duplicates_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 { continue; }
        let hash = parts[1].trim().to_string();
        groups.entry(hash).or_default().push(trimmed.to_string());
    }
    let mut dup_lines: Vec<String> = groups
        .into_values()
        .filter(|v| v.len() > 1)
        .flatten()
        .collect();
    dup_lines.sort();
    for line in dup_lines {
        writeln!(out, "{line}")?;
    }
    Ok(())
}
```

**Mode:** `Duplicates`, dispatch on `"duplicates"`

**main.rs dispatch:**
```rust
if let Mode::Duplicates = cli.mode() {
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash duplicates <manifest>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::duplicates::duplicates_manifest(manifest.as_ref(), &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/duplicates_tests.rs`:**

Manifest: 5 entries where file1.exe and file3.dll share a hash, file2.bin and file4.txt share another hash, file5.jpg is unique.

1. `test_duplicates_finds_shared_hashes` — output contains both entries sharing same hash
2. `test_duplicates_emits_all_occurrences` — for two pairs sharing hashes, all 4 entries appear
3. `test_duplicates_excludes_unique_entries` — unique file5.jpg does NOT appear in output
4. `test_duplicates_missing_manifest_fails` — non-zero exit
5. `test_duplicates_output_to_file` — `-o` file contains duplicate entries

---

## Task 2: `blazehash repair`

Normalize manifest formatting: strip blank lines, normalize multi-space separators to exactly two spaces, remove malformed data lines (not matching `algo  hash  path`), preserve headers.

**Behavior:**
- Reads a manifest
- Emits header lines unchanged
- Normalizes data lines: splits on 2+ whitespace runs into exactly `algo  hash  path`
- Drops lines that cannot be parsed into 3 fields
- Blank lines dropped (not emitted)
- Supports `-o <file>`
- No new CLI fields needed
- Module: `repair`

**`src/commands/repair.rs`:**
```rust
use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn repair_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{trimmed}")?;
            continue;
        }
        // Split on any run of 2+ spaces to normalize separators
        let parts: Vec<&str> = trimmed
            .splitn(3, |_| false) // placeholder
            .collect();
        // Use regex-free approach: find first and second double-space
        let normalized = normalize_data_line(trimmed);
        if let Some(line_out) = normalized {
            writeln!(out, "{line_out}")?;
        }
    }
    Ok(())
}

fn normalize_data_line(line: &str) -> Option<String> {
    // Split on first occurrence of 2+ consecutive spaces
    let sep = "  ";
    let first = line.find(sep)?;
    let algo = line[..first].trim();
    let rest = line[first + 2..].trim_start();
    let second = rest.find(sep)?;
    let hash = rest[..second].trim();
    let path = rest[second + 2..].trim();
    if algo.is_empty() || hash.is_empty() || path.is_empty() {
        return None;
    }
    Some(format!("{algo}  {hash}  {path}"))
}
```

**Mode:** `Repair`, dispatch on `"repair"`

**main.rs dispatch:**
```rust
if let Mode::Repair = cli.mode() {
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash repair <manifest>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::repair::repair_manifest(manifest.as_ref(), &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/repair_tests.rs`:**

1. `test_repair_removes_blank_lines` — manifest with blank lines; output has no blank lines
2. `test_repair_preserves_headers` — `## case:` line preserved unchanged
3. `test_repair_normalizes_extra_spaces` — entry with 4 spaces between fields normalized to 2
4. `test_repair_drops_malformed_lines` — line with only one field dropped
5. `test_repair_output_to_file` — `-o` file is clean

---

## Task 3: `blazehash sym-diff`

Symmetric difference of two manifests: entries whose path appears in A or B but not both.

**Behavior:**
- Reads two manifest paths: `paths[1]` and `paths[2]`
- Collects path sets from each manifest
- Emits entries from A whose path is NOT in B, then entries from B whose path is NOT in A
- Output format: same as manifest data lines
- Headers from neither manifest appear in output (pure data output)
- Entries from A-only come first, then B-only
- Supports `-o <file>`
- No new CLI fields needed
- Module: `sym_diff`

**`src/commands/sym_diff.rs`:**
```rust
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

fn parse_entries(manifest_path: &Path) -> Result<Vec<(String, String, String)>> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            entries.push((
                parts[0].trim().to_string(),
                parts[1].trim().to_string(),
                parts[2].trim().to_string(),
            ));
        }
    }
    Ok(entries)
}

pub fn sym_diff_manifests(
    path_a: &Path,
    path_b: &Path,
    out: &mut impl Write,
) -> Result<()> {
    let a = parse_entries(path_a)?;
    let b = parse_entries(path_b)?;
    let paths_b: HashSet<&str> = b.iter().map(|(_, _, p)| p.as_str()).collect();
    let paths_a: HashSet<&str> = a.iter().map(|(_, _, p)| p.as_str()).collect();
    for (algo, hash, path) in &a {
        if !paths_b.contains(path.as_str()) {
            writeln!(out, "{algo}  {hash}  {path}")?;
        }
    }
    for (algo, hash, path) in &b {
        if !paths_a.contains(path.as_str()) {
            writeln!(out, "{algo}  {hash}  {path}")?;
        }
    }
    Ok(())
}
```

**Mode:** `SymDiff`, dispatch on `"sym-diff"`

**main.rs dispatch:**
```rust
if let Mode::SymDiff = cli.mode() {
    let a = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash sym-diff <manifest-a> <manifest-b>"))?;
    let b = cli.paths.get(2)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash sym-diff <manifest-a> <manifest-b>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::sym_diff::sym_diff_manifests(a.as_ref(), b.as_ref(), &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/sym_diff_tests.rs`:**

A: file1.txt, file2.txt, shared.txt
B: file3.txt, file4.txt, shared.txt

1. `test_sym_diff_finds_a_only_entries` — file1.txt and file2.txt appear (in A, not B)
2. `test_sym_diff_finds_b_only_entries` — file3.txt and file4.txt appear (in B, not A)
3. `test_sym_diff_excludes_shared_entries` — shared.txt does NOT appear
4. `test_sym_diff_missing_manifest_fails` — non-zero exit when manifest missing
5. `test_sym_diff_output_to_file` — `-o` file contains A-only and B-only entries

---

## Task 4: `blazehash first`

Keep only the first occurrence of each path (complement to `uniq` which keeps the last).

**Behavior:**
- Reads a manifest
- Preserves headers
- For each path, keeps the first occurrence; subsequent duplicate paths dropped
- Order of kept entries matches original order
- Supports `-o <file>`
- No new CLI fields needed
- Module: `first_cmd`

**`src/commands/first_cmd.rs`:**
```rust
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

pub fn first_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut seen: HashSet<String> = HashSet::new();
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
        let path = parts[2].trim().to_string();
        if seen.insert(path) {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}
```

**Mode:** `First`, dispatch on `"first"`

**main.rs dispatch:**
```rust
if let Mode::First = cli.mode() {
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash first <manifest>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::first_cmd::first_manifest(manifest.as_ref(), &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/first_tests.rs`:**

Manifest with file1.txt appearing twice (different hashes), file2.txt once.

1. `test_first_keeps_first_occurrence` — file1.txt's first hash kept, second dropped
2. `test_first_unique_paths_unaffected` — file2.txt (appears once) still in output
3. `test_first_preserves_headers` — `## case:` header preserved
4. `test_first_missing_manifest_fails` — non-zero exit
5. `test_first_output_to_file` — `-o` file has no duplicate paths

---

## Task 5: `blazehash annotate`

Append a `## note: <message>` header to a manifest (shorthand for common tagging).

**Behavior:**
- Reads a manifest
- Appends `## note: <message>` as the last header line (before data entries)
- If a `## note:` line already exists, REPLACES it (only one note allowed)
- Requires `--note <MESSAGE>` flag
- Supports `-o <file>`
- New CLI field: `annotate_note: Option<String>` (`--note`)
- Module: `annotate`

**New CLI field:**
```rust
/// Note message for blazehash annotate
#[arg(long = "note")]
pub annotate_note: Option<String>,
```

**`src/commands/annotate.rs`:**
```rust
use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn annotate_manifest(manifest_path: &Path, note: &str, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<String> = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    let mut has_note = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            if trimmed.starts_with("## note:") || trimmed.starts_with("##note:") {
                headers.push(format!("## note: {note}"));
                has_note = true;
            } else {
                headers.push(trimmed.to_string());
            }
        } else {
            entries.push(line.to_string());
        }
    }
    if !has_note {
        headers.push(format!("## note: {note}"));
    }
    for h in &headers { writeln!(out, "{h}")?; }
    for e in &entries { writeln!(out, "{e}")?; }
    Ok(())
}
```

**Mode:** `Annotate`, dispatch on `"annotate"`

**main.rs dispatch:**
```rust
if let Mode::Annotate = cli.mode() {
    let note = cli.annotate_note.as_deref()
        .ok_or_else(|| anyhow::anyhow!("--note is required for blazehash annotate"))?;
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash annotate <manifest> --note <message>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::annotate::annotate_manifest(manifest.as_ref(), note, &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/annotate_tests.rs`:**

1. `test_annotate_adds_note_header` — manifest with no note; output contains `## note: test message`
2. `test_annotate_replaces_existing_note` — manifest has `## note: old`; output has new note, old absent, appears exactly once
3. `test_annotate_preserves_other_headers` — `## case: X` still in output
4. `test_annotate_preserves_data_entries` — data lines unchanged
5. `test_annotate_output_to_file` — `-o` file contains `## note:`

---

## Commit sequence (per task)

```bash
export GITSIGN_CREDENTIAL_CACHE="/Users/4n6h4x0r/.cache/sigstore/gitsign/cache.sock"

# RED
cargo test --all-features --test <name>_tests 2>&1 | tail -10  # confirm FAIL
git add tests/<name>_tests.rs
git commit -m "test(RED): add failing tests for blazehash <name>"

# GREEN
cargo test --all-features --test <name>_tests 2>&1 | tail -5   # confirm PASS
cargo clippy --all-features -- -D warnings 2>&1 | grep "^error" | head -5
git add src/commands/<module>.rs src/commands/mod.rs src/cli.rs src/main.rs
git commit -m "feat: blazehash <name> — <one-line description>"
```

After Task 5 GREEN: run full suite + push.
