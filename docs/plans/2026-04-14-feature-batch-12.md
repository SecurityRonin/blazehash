# blazehash Feature Batch 12 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Five manifest utility commands — tally, exclude, contains, path-only, hash-only.

**Architecture:** Standard Mode dispatch pattern. All commands follow the same four-file touch pattern:
1. `src/commands/<module>.rs` — implementation function
2. `src/commands/mod.rs` — `pub mod <module>;` declaration
3. `src/cli.rs` — new `Mode::X` variant, `mode()` branch, optional new `#[arg]` field(s)
4. `src/main.rs` — `if let Mode::X` dispatch block before the hash-walk block; `Mode::X => unreachable!()` in the exhaustive match at the bottom

**Format reminder:** Manifest data lines are `algo  hash  path` with exactly two spaces between each field. Header lines begin with `##` or `%%`. Empty lines are whitespace-only.

**Two commits per task:** RED (failing tests only) then GREEN (implementation + passing tests + zero clippy warnings).

---

## Task 1: `blazehash tally`

Groups manifest entries by a key field and prints `<count>\t<key>` sorted by count descending.
- `--tally-by ext|dir|algo` (default: `ext`)
- `ext` = file extension (`.exe`, `(none)` if absent)
- `dir` = parent directory of path
- `algo` = hash algorithm name
- Header lines skipped; output to stdout or `-o`

**New CLI field:**
```rust
#[arg(long = "tally-by", value_name = "FIELD", default_value = "ext",
      value_parser = ["ext", "dir", "algo"])]
pub tally_by: String,
```

**Mode variant:** `Tally`

**mode() branch:** `"tally"` → `Mode::Tally`

**`src/commands/tally.rs`:**
```rust
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

pub fn tally_manifest(manifest_path: &Path, key: &str, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut counts: HashMap<String, u64> = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 { continue; }
        let algo = parts[0].trim();
        let path = parts[2].trim();
        let bucket = match key {
            "algo" => algo.to_string(),
            "dir" => {
                std::path::Path::new(path)
                    .parent()
                    .map(|d| d.to_string_lossy().into_owned())
                    .unwrap_or_else(|| ".".to_string())
            }
            _ => {
                match std::path::Path::new(path).extension().and_then(|e| e.to_str()) {
                    Some(ext) => format!(".{ext}"),
                    None => "(none)".to_string(),
                }
            }
        };
        *counts.entry(bucket).or_insert(0) += 1;
    }
    let mut pairs: Vec<(u64, String)> = counts.into_iter().map(|(k, v)| (v, k)).collect();
    pairs.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (count, bucket) in pairs {
        writeln!(out, "{count}\t{bucket}")?;
    }
    Ok(())
}
```

**main.rs dispatch:**
```rust
if let Mode::Tally = cli.mode() {
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash tally <manifest> [--tally-by ext|dir|algo]"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::tally::tally_manifest(manifest.as_ref(), &cli.tally_by, &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/tally_tests.rs`:**
- `test_tally_by_ext_default` — no flag, `.exe` has count 2 and appears first
- `test_tally_by_algo` — `--tally-by algo`, sha256=3, blake3=2
- `test_tally_by_dir` — `--tally-by dir`, `/evidence` and `/docs` buckets appear
- `test_tally_missing_manifest_fails` — non-zero exit
- `test_tally_output_to_file` — `-o`, file contains algo buckets

---

## Task 2: `blazehash exclude`

Drops entries whose path matches a glob pattern. Inverse of `filter --include`.
- `--exclude-pattern <GLOB>` using `globset` crate (already in Cargo.toml)
- Headers preserved; output to stdout or `-o`

**New CLI field:**
```rust
#[arg(long = "exclude-pattern", value_name = "GLOB")]
pub exclude_pattern: Option<String>,
```

**Mode variant:** `Exclude`

**`src/commands/exclude.rs`:**
```rust
use anyhow::{bail, Result};
use globset::GlobBuilder;
use std::io::Write;
use std::path::Path;

pub fn exclude_manifest(manifest_path: &Path, pattern: &str, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let glob = GlobBuilder::new(pattern)
        .literal_separator(false)
        .build()
        .map_err(|e| anyhow::anyhow!("invalid glob {pattern:?}: {e}"))?
        .compile_matcher();
    let content = std::fs::read_to_string(manifest_path)?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
            writeln!(out, "{line}")?;
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 { writeln!(out, "{line}")?; continue; }
        let path = parts[2].trim();
        if !glob.is_match(path) {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}
```

**main.rs dispatch:**
```rust
if let Mode::Exclude = cli.mode() {
    let pattern = cli.exclude_pattern.as_deref()
        .ok_or_else(|| anyhow::anyhow!("--exclude-pattern is required for blazehash exclude"))?;
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash exclude <manifest> --exclude-pattern <GLOB>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::exclude::exclude_manifest(manifest.as_ref(), pattern, &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/exclude_tests.rs`:**
- `test_exclude_drops_matching_entries` — `*.tmp` removes scratch.tmp
- `test_exclude_preserves_headers` — `## case:` still present
- `test_exclude_glob_with_directory_prefix` — `/evidence/*` removes both evidence entries
- `test_exclude_no_matches_passes_all_through` — unmatched pattern → all entries kept
- `test_exclude_output_to_file` — `-o` file omits excluded entry

---

## Task 3: `blazehash contains`

Tests if a manifest contains a hash or path matching a search term (substring). Exits 0 if found, 1 if not.
- Term is `paths[2]` (third positional arg): `blazehash contains manifest.hash <term>`
- No new CLI fields needed
- Prints `FOUND  <path>` for each match or `NOT FOUND`
- Module: `contains_cmd`

**Mode variant:** `Contains`

**`src/commands/contains_cmd.rs`:**
```rust
use anyhow::{bail, Result};
use std::path::Path;

pub fn contains_manifest(manifest_path: &Path, term: &str) -> Result<bool> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let mut found = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') { continue; }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 { continue; }
        let hash = parts[1].trim();
        let path = parts[2].trim();
        if hash.contains(term) || path.contains(term) {
            println!("FOUND  {path}");
            found = true;
        }
    }
    Ok(found)
}
```

**main.rs dispatch:**
```rust
if let Mode::Contains = cli.mode() {
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash contains <manifest> <term>"))?;
    let term = cli.paths.get(2).and_then(|p| p.to_str())
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash contains <manifest> <term>"))?;
    let found = crate::commands::contains_cmd::contains_manifest(manifest.as_ref(), term)?;
    if !found {
        println!("NOT FOUND");
        std::process::exit(1);
    }
    return Ok(());
}
```

**5 tests in `tests/contains_tests.rs`:**
- `test_contains_found_by_path_substring` — "malware" matches path, exit 0, prints FOUND
- `test_contains_found_by_hash_substring` — "deadbeef" matches hash, exit 0
- `test_contains_not_found_exits_one` — unmatched term, exit 1, prints NOT FOUND
- `test_contains_missing_manifest_errors` — non-zero exit, non-empty stderr
- `test_contains_multiple_matches_all_printed` — two matching entries, both printed

---

## Task 4: `blazehash path-only`

Emits just the path column, one per line. Headers skipped.
- No new CLI fields
- Output to stdout or `-o`
- Module: `path_only`

**Mode variant:** `PathOnly`

**`src/commands/path_only.rs`:**
```rust
use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn path_only_manifest(manifest_path: &Path, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') { continue; }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() == 3 {
            writeln!(out, "{}", parts[2].trim())?;
        }
    }
    Ok(())
}
```

**main.rs dispatch:**
```rust
if let Mode::PathOnly = cli.mode() {
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash path-only <manifest>"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::path_only::path_only_manifest(manifest.as_ref(), &mut out)?;
    return Ok(());
}
```

**5 tests in `tests/path_only_tests.rs`:**
- `test_path_only_emits_paths_one_per_line` — 3 entries → 3 output lines, each is a path
- `test_path_only_skips_headers` — no `##` or `%%` in output
- `test_path_only_no_algo_or_hash_in_output` — no "sha256" or hash prefix in output
- `test_path_only_missing_manifest_fails` — non-zero exit
- `test_path_only_output_to_file` — `-o` file has 3 lines

---

## Task 5: `blazehash hash-only`

Emits bare hash values, optionally filtered by algorithm. No path, no algo prefix.
- `--hash-only-algo <ALGO>` (optional; if omitted, all hashes emitted)
- Case-insensitive algo matching
- Headers skipped; output to stdout or `-o`
- Module: `hash_only`

**New CLI field:**
```rust
#[arg(long = "hash-only-algo", value_name = "ALGO")]
pub hash_only_algo: Option<String>,
```

**Mode variant:** `HashOnly`

**`src/commands/hash_only.rs`:**
```rust
use anyhow::{bail, Result};
use std::io::Write;
use std::path::Path;

pub fn hash_only_manifest(manifest_path: &Path, algo_filter: Option<&str>, out: &mut impl Write) -> Result<()> {
    if !manifest_path.exists() {
        bail!("manifest not found: {}", manifest_path.display());
    }
    let content = std::fs::read_to_string(manifest_path)?;
    let filter_upper = algo_filter.map(|a| a.to_uppercase());
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') { continue; }
        let parts: Vec<&str> = trimmed.splitn(3, "  ").collect();
        if parts.len() != 3 { continue; }
        let entry_algo = parts[0].trim();
        let hash = parts[1].trim();
        if let Some(ref required) = filter_upper {
            if entry_algo.to_uppercase() != *required { continue; }
        }
        writeln!(out, "{hash}")?;
    }
    Ok(())
}
```

**main.rs dispatch:**
```rust
if let Mode::HashOnly = cli.mode() {
    let manifest = cli.paths.get(1)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash hash-only <manifest> [--hash-only-algo ALGO]"))?;
    let mut out = crate::commands::output_writer(cli.output.as_deref())?;
    crate::commands::hash_only::hash_only_manifest(
        manifest.as_ref(),
        cli.hash_only_algo.as_deref(),
        &mut out,
    )?;
    return Ok(());
}
```

**5 tests in `tests/hash_only_tests.rs`:**
- `test_hash_only_emits_hashes_for_algo` — `--hash-only-algo sha256` → 2 sha256 hashes
- `test_hash_only_skips_other_algos` — blake3 hash not in sha256-filtered output
- `test_hash_only_algo_case_insensitive` — `--hash-only-algo SHA256` works
- `test_hash_only_no_algo_filter_emits_all_hashes` — no flag → all 3 hashes
- `test_hash_only_output_to_file` — `-o` file has 1 blake3 hash

---

## Commit sequence summary

For each task: RED commit (`tests/<name>.rs` only, confirmed failing) then GREEN commit (all implementation files, confirmed passing + zero clippy errors).

Total: 10 commits for 5 tasks.
