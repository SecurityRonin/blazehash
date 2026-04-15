# blazehash Feature Batch 14 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Five manifest ordering and deduplication commands — shuffle, reverse, unique-hash, balance, interleave.

**Architecture:** Standard Mode dispatch pattern (same as all previous batches).
Manifest data lines: `algo  hash  path` (two spaces). Headers: `##` or `%%`.
Two commits per task: RED (failing tests) then GREEN (implementation, passing + zero clippy).

---

## Task 1: `blazehash shuffle`

Randomly reorder manifest entries (useful for random sampling baselines and test fixtures).

**Behavior:**
- Reads a manifest (first positional path after "shuffle")
- Preserves headers (emitted first, in original order)
- Randomly shuffles data entries using `rand::seq::SliceRandom::shuffle`
- Optional `--seed <u64>` for reproducible output
- Supports `-o <file>`
- New CLI fields: `shuffle_seed: Option<u64>` (`--seed`)
- Module: `shuffle`

**`src/commands/shuffle.rs`:**
```rust
use anyhow::{bail, Result};
use rand::{SeedableRng, seq::SliceRandom};
use rand::rngs::StdRng;
use std::io::Write;
use std::path::Path;

pub fn shuffle_manifest(manifest_path: &Path, seed: Option<u64>, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<String> = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(trimmed.to_string());
        } else {
            entries.push(line.to_string());
        }
    }
    let mut rng: StdRng = match seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };
    entries.shuffle(&mut rng);
    for h in &headers { writeln!(out, "{h}")?; }
    for e in &entries { writeln!(out, "{e}")?; }
    Ok(())
}
```

**Mode:** `Shuffle`, dispatch on `"shuffle"`

**New CLI field:**
```rust
/// Seed for blazehash shuffle (reproducible output)
#[arg(long = "seed")]
pub shuffle_seed: Option<u64>,
```

**main.rs dispatch:**
```rust
if let Mode::Shuffle = cli.mode() {
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash shuffle <manifest>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::shuffle::shuffle_manifest(manifest.as_ref(), cli.shuffle_seed, &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/shuffle_tests.rs`:**

Manifest: 5 entries with distinct paths.

1. `test_shuffle_contains_all_entries` — output has same entries as input (just reordered)
2. `test_shuffle_preserves_headers` — `## case:` header still in output
3. `test_shuffle_seed_is_reproducible` — same seed → same order across two runs
4. `test_shuffle_missing_manifest_fails` — non-zero exit
5. `test_shuffle_output_to_file` — `-o` file contains all entries

---

## Task 2: `blazehash reverse`

Reverse the entry order in a manifest (last entry becomes first).

**Behavior:**
- Reads a manifest
- Preserves headers (emitted first, in original order)
- Reverses data entries
- Supports `-o <file>`
- No new CLI fields
- Module: `reverse`

**`src/commands/reverse.rs`:**
```rust
use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn reverse_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<String> = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(trimmed.to_string());
        } else {
            entries.push(line.to_string());
        }
    }
    entries.reverse();
    for h in &headers { writeln!(out, "{h}")?; }
    for e in &entries { writeln!(out, "{e}")?; }
    Ok(())
}
```

**Mode:** `Reverse`, dispatch on `"reverse"`

**main.rs dispatch:**
```rust
if let Mode::Reverse = cli.mode() {
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash reverse <manifest>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::reverse::reverse_manifest(manifest.as_ref(), &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/reverse_tests.rs`:**

Manifest: 3 entries: file1.txt, file2.txt, file3.txt (in that order).

1. `test_reverse_reverses_entry_order` — file3.txt appears before file1.txt in output
2. `test_reverse_preserves_headers` — `## case:` header in output
3. `test_reverse_double_reverse_is_identity` — reversing twice gives original order
4. `test_reverse_missing_manifest_fails` — non-zero exit
5. `test_reverse_output_to_file` — `-o` file has entries in reverse order

---

## Task 3: `blazehash unique-hash`

Keep only the first occurrence of each unique hash value (complement to `duplicates` which shows all duplicates).

**Behavior:**
- Reads a manifest
- Preserves headers
- For each hash value, keeps the first entry with that hash; subsequent entries sharing the hash are dropped
- Order of kept entries matches original order
- Supports `-o <file>`
- No new CLI fields
- Module: `unique_hash`

**`src/commands/unique_hash.rs`:**
```rust
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

pub fn unique_hash_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut seen: HashSet<String> = HashSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{trimmed}")?;
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 {
            writeln!(out, "{line}")?;
            continue;
        }
        let hash = parts[1].trim().to_string();
        if seen.insert(hash) {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}
```

**Mode:** `UniqueHash`, dispatch on `"unique-hash"`

**main.rs dispatch:**
```rust
if let Mode::UniqueHash = cli.mode() {
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash unique-hash <manifest>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::unique_hash::unique_hash_manifest(manifest.as_ref(), &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/unique_hash_tests.rs`:**

Manifest: file1.exe and file3.dll share hash H1, file2.bin and file4.txt share hash H2, file5.jpg has unique hash H3.

1. `test_unique_hash_keeps_first_of_each_hash` — only file1.exe and file2.bin appear (first with H1, first with H2)
2. `test_unique_hash_keeps_unique_entries` — file5.jpg (unique hash) appears
3. `test_unique_hash_drops_duplicate_hash_entries` — file3.dll and file4.txt do NOT appear
4. `test_unique_hash_missing_manifest_fails` — non-zero exit
5. `test_unique_hash_output_to_file` — `-o` file has only one entry per hash

---

## Task 4: `blazehash balance`

Split a manifest into N roughly equal parts (complement to `split` which uses fixed entry count per part).

**Behavior:**
- Reads a manifest (first positional path after "balance")
- Requires `--parts <N>` flag (N ≥ 1)
- Writes to `<stem>_part001.hash`, `<stem>_part002.hash`, etc. (same directory as input)
- Each part gets the headers from the original manifest
- Distributes entries as evenly as possible (first parts get one extra entry if not divisible)
- Supports `-o <dir>` to override output directory
- New CLI fields: `balance_parts: Option<usize>` (`--parts`)
- Module: `balance`

**`src/commands/balance.rs`:**
```rust
use anyhow::{bail, Result};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn balance_manifest(manifest_path: &Path, parts: usize, out_dir: Option<&Path>) -> Result<Vec<std::path::PathBuf>> {
    if parts == 0 {
        bail!("--parts must be >= 1");
    }
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut headers: Vec<String> = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(trimmed.to_string());
        } else {
            entries.push(line.to_string());
        }
    }
    let stem = manifest_path.file_stem()
        .unwrap_or_default().to_string_lossy().to_string();
    let dir = out_dir.unwrap_or_else(|| manifest_path.parent().unwrap_or(Path::new(".")));
    let total = entries.len();
    let base_size = total / parts;
    let extras = total % parts;
    let mut offset = 0;
    let mut out_paths = Vec::new();
    for i in 0..parts {
        let chunk_size = base_size + if i < extras { 1 } else { 0 };
        let part_path = dir.join(format!("{stem}_part{:03}.hash", i + 1));
        let mut f = File::create(&part_path)?;
        for h in &headers { writeln!(f, "{h}")?; }
        for e in &entries[offset..offset + chunk_size] { writeln!(f, "{e}")?; }
        offset += chunk_size;
        out_paths.push(part_path);
    }
    Ok(out_paths)
}
```

**Mode:** `Balance`, dispatch on `"balance"`

**New CLI field:**
```rust
/// Number of parts for blazehash balance
#[arg(long = "parts")]
pub balance_parts: Option<usize>,
```

**main.rs dispatch:**
```rust
if let Mode::Balance = cli.mode() {
    let parts = cli.balance_parts
        .ok_or_else(|| anyhow::anyhow!("--parts is required for blazehash balance"))?;
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash balance <manifest> --parts <N>"))?;
    let out_dir = cli.output.as_deref();
    let paths = crate::commands::balance::balance_manifest(manifest.as_ref(), parts, out_dir)?;
    for p in paths {
        println!("{}", p.display());
    }
    return Ok(());
}
```

**5 tests in `tests/balance_tests.rs`:**

Manifest: 10 entries.

1. `test_balance_creates_correct_number_of_parts` — `--parts 3` creates 3 files
2. `test_balance_distributes_entries_evenly` — 10 entries / 3 parts → parts have 4,3,3 entries
3. `test_balance_parts_cover_all_entries` — union of all parts contains all 10 entries
4. `test_balance_missing_manifest_fails` — non-zero exit
5. `test_balance_parts_contain_headers` — each part file starts with the header line

---

## Task 5: `blazehash interleave`

Interleave entries from two manifests in alternating order (A₁ B₁ A₂ B₂ …).

**Behavior:**
- Reads two manifest paths: `paths[1]` and `paths[2]`
- Headers from manifest A emitted first; headers from B skipped
- Entries interleaved: one from A, one from B, one from A, …
- Remaining entries from the longer manifest appended after
- Supports `-o <file>`
- No new CLI fields
- Module: `interleave`

**`src/commands/interleave.rs`:**
```rust
use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

fn read_manifest(path: &Path) -> Result<(Vec<String>, Vec<String>)> {
    if !path.exists() {
        bail!("manifest not found: {}", path.display());
    }
    let content = std::fs::read_to_string(path)?;
    let mut headers = Vec::new();
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        if trimmed.starts_with('#') || trimmed.starts_with('%') {
            headers.push(trimmed.to_string());
        } else {
            entries.push(line.to_string());
        }
    }
    Ok((headers, entries))
}

pub fn interleave_manifests(path_a: &Path, path_b: &Path, out: &mut impl Write) -> Result<()> {
    let (headers_a, entries_a) = read_manifest(path_a)?;
    let (_, entries_b) = read_manifest(path_b)?;
    for h in &headers_a { writeln!(out, "{h}")?; }
    let len = entries_a.len().max(entries_b.len());
    for i in 0..len {
        if let Some(e) = entries_a.get(i) { writeln!(out, "{e}")?; }
        if let Some(e) = entries_b.get(i) { writeln!(out, "{e}")?; }
    }
    Ok(())
}
```

**Mode:** `Interleave`, dispatch on `"interleave"`

**main.rs dispatch:**
```rust
if let Mode::Interleave = cli.mode() {
    let a = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash interleave <manifest-a> <manifest-b>"))?;
    let b = cli.paths.get(2)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash interleave <manifest-a> <manifest-b>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::interleave::interleave_manifests(a.as_ref(), b.as_ref(), &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/interleave_tests.rs`:**

A: file_a1.txt, file_a2.txt, file_a3.txt
B: file_b1.txt, file_b2.txt

1. `test_interleave_alternates_entries` — output order is a1, b1, a2, b2, a3
2. `test_interleave_preserves_headers_from_a` — `## case: A` header in output
3. `test_interleave_skips_headers_from_b` — `## case: B` header NOT in output
4. `test_interleave_missing_manifest_fails` — non-zero exit when a manifest missing
5. `test_interleave_output_to_file` — `-o` file contains all 5 entries

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
