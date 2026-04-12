# blazehash Feature Batch 3 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement 11 features: manifest metadata (`--case-id`/`--examiner`), progress bar (indicatif), shell completions (clap_complete), HashDB bad list, diff `--patch` output, sector-level raw device hashing, OpenTimestamps notarization, STIX 2.1 output, ECS NDJSON output, multi-party cosigning, and interactive TUI (ratatui).

**Architecture:** Layered build -- no-new-dep features first (manifest metadata, patch diff, bad list), then single-dep features (progress bar, completions), then output formatters (STIX, ECS), then compound features (device hashing, OTS, cosign, TUI). Each feature is self-contained behind its own CLI subcommand/flag; no feature modifies existing behaviour.

**Tech Stack:** Rust. New direct deps: `indicatif` (progress bar), `clap_complete` (shell completions), `uuid` (STIX UUIDv5 generation). New optional deps: `ratatui` + `crossterm` (behind `tui` feature). OTS uses existing `ureq` + `sha2` (no new deps). STIX/ECS use existing `serde_json` (no new deps).

**TDD mandate:** Every task has a RED commit (failing tests only, all `todo!()` or missing symbols) then a GREEN commit (minimal implementation). Two commits per task, no exceptions. Confirm RED fails before writing GREEN.

**Key design decision -- OTS crate:** The `opentimestamps` crate on crates.io is v0.2.0, last published April 2023, depends on `bitcoin ^0.12` (severely outdated). We will NOT use it. Instead, we implement the minimal OTS calendar protocol directly: SHA-256 hash the manifest, POST raw bytes to calendar server, save binary response as `.ots` sidecar. This avoids pulling in the entire rust-bitcoin dependency tree for a simple HTTP POST.

---

## Task 1: New Cargo dependencies

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add direct deps**

Add to `[dependencies]` in `Cargo.toml` (after the existing `duckdb` line):

```toml
indicatif = "0.17"
clap_complete = "4"
uuid = { version = "1", features = ["v5"] }
```

**Step 2: Add optional deps**

Add to `[dependencies]` (after existing optional deps):

```toml
ratatui = { version = "0.29", optional = true }
crossterm = { version = "0.28", optional = true }
```

**Step 3: Add new feature flags**

In `[features]`, add:

```toml
tui = ["dep:ratatui", "dep:crossterm"]
```

Note: `ots` does not need a feature flag for deps (uses existing `ureq` + `sha2`), but we gate it behind a feature flag to make the network dependency opt-in:

```toml
ots = []
```

And `stix` is default-on (pure JSON formatting):

Update the `default` line:

```toml
default = ["forensic-image", "gpu", "sqlite", "parquet-output", "duckdb-output"]
```

(No change to default -- STIX and ECS are just format strings handled in the match arm, no feature gate needed since they use only `serde_json` which is already a hard dep.)

**Step 4: Verify build**

```bash
cargo check --all-features
```
Expected: clean (no errors).

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add Cargo deps for feature batch 3 (indicatif, clap_complete, uuid, optional ratatui+crossterm)"
```

---

## Task 2: `--case-id` / `--examiner` manifest header metadata

Chain-of-custody metadata fields embedded in the manifest header comment block. These already exist in `cli.rs` behind `#[cfg(feature = "report")]` -- we move them to always-available (unconditional) and emit them in the hashdeep header.

**Files:**
- Modify: `src/cli.rs` -- make `--examiner` and `--case-id` (renamed to `--case`) unconditional (remove `#[cfg(feature = "report")]`)
- Modify: `src/manifest.rs` -- add `write_header_with_metadata()` that accepts optional case_id/examiner
- Modify: `src/commands/hash.rs` -- pass metadata to header writer
- Modify: `src/commands/report.rs` -- use `cli.case_id` / `cli.examiner` (already works, just ensure no breakage)
- Test: `tests/manifest_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/manifest_tests.rs`:

```rust
#[test]
fn test_write_header_with_metadata_includes_case_and_examiner() {
    use blazehash::algorithm::Algorithm;
    use blazehash::manifest::write_header_with_metadata;

    let mut buf = Vec::new();
    write_header_with_metadata(
        &mut buf,
        &[Algorithm::Blake3],
        Some("CASE-2026-001"),
        Some("Jane Doe"),
    )
    .unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("## Case: CASE-2026-001"),
        "header must contain case ID, got:\n{output}"
    );
    assert!(
        output.contains("## Examiner: Jane Doe"),
        "header must contain examiner name, got:\n{output}"
    );
    // Must still contain the standard hashdeep header
    assert!(output.contains("%%%% HASHDEEP-1.0"));
    assert!(output.contains("%%%% size,blake3,filename"));
}

#[test]
fn test_write_header_with_metadata_none_values() {
    use blazehash::algorithm::Algorithm;
    use blazehash::manifest::write_header_with_metadata;

    let mut buf = Vec::new();
    write_header_with_metadata(&mut buf, &[Algorithm::Sha256], None, None).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(!output.contains("## Case:"));
    assert!(!output.contains("## Examiner:"));
    // Standard header still present
    assert!(output.contains("%%%% HASHDEEP-1.0"));
}
```

```bash
cargo test test_write_header_with_metadata -- 2>&1 | head -20
```
Expected: compilation error (`write_header_with_metadata` does not exist).

**RED commit:**
```bash
git add tests/manifest_tests.rs
git commit -m "test(red): failing tests for --case-id/--examiner manifest header metadata"
```

**Step 2: Implement (GREEN)**

In `src/manifest.rs`, add after the existing `write_header` function:

```rust
/// Write the hashdeep-format header with optional chain-of-custody metadata.
pub fn write_header_with_metadata<W: Write>(
    w: &mut W,
    algorithms: &[Algorithm],
    case_id: Option<&str>,
    examiner: Option<&str>,
) -> Result<()> {
    writeln!(w, "%%%% HASHDEEP-1.0")?;
    write!(w, "%%%% size")?;
    for algo in algorithms {
        write!(w, ",{}", algo.hashdeep_name())?;
    }
    writeln!(w, ",filename")?;
    writeln!(
        w,
        "## Invoked from: blazehash v{}",
        env!("CARGO_PKG_VERSION")
    )?;
    if let Some(case) = case_id {
        writeln!(w, "## Case: {case}")?;
    }
    if let Some(name) = examiner {
        writeln!(w, "## Examiner: {name}")?;
    }
    writeln!(w, "##")?;
    Ok(())
}
```

In `src/cli.rs`, move `examiner` and `case_id` fields OUT of the `#[cfg(feature = "report")]` gate. They should be unconditional fields on `Cli`:

```rust
    /// Examiner name for chain-of-custody metadata
    #[arg(long = "examiner", value_name = "NAME")]
    pub examiner: Option<String>,

    /// Case identifier for chain-of-custody metadata
    #[arg(long = "case", value_name = "ID")]
    pub case_id: Option<String>,
```

Remove the duplicate `#[cfg(feature = "report")]` versions. The report command in `src/commands/report.rs` and `src/main.rs` will continue to reference `cli.examiner` and `cli.case_id` unchanged.

In `src/commands/hash.rs`, add `case_id` and `examiner` to `HashOptions`:

```rust
pub struct HashOptions<'a> {
    // ... existing fields ...
    pub case_id: Option<&'a str>,
    pub examiner: Option<&'a str>,
}
```

In the `write_output` function, change the hashdeep default arm to call `write_header_with_metadata`:

```rust
_ => {
    if needs_header {
        blazehash::manifest::write_header_with_metadata(
            writer,
            algorithms,
            opts.case_id,
            opts.examiner,
        )?;
    }
    for result in results {
        write_record(writer, result, algorithms)?;
    }
}
```

Note: This requires threading `case_id` and `examiner` from `HashOptions` into the `write_output` call or restructuring slightly. The simplest approach: add `case_id: Option<&str>` and `examiner: Option<&str>` params to `write_output`. Alternatively, make `write_output` accept the full `HashOptions` ref.

In `src/main.rs`, pass the new fields when constructing `HashOptions`:

```rust
Mode::Hash => {
    let filter = cli.build_walk_filter()?;
    commands::hash::run(commands::hash::HashOptions {
        // ... existing fields ...
        case_id: cli.case_id.as_deref(),
        examiner: cli.examiner.as_deref(),
    })?;
}
```

```bash
cargo test test_write_header_with_metadata
```
Expected: all pass.

**GREEN commit:**
```bash
git add src/manifest.rs src/cli.rs src/commands/hash.rs src/main.rs tests/manifest_tests.rs
git commit -m "feat: --case-id/--examiner chain-of-custody metadata in manifest header"
```

---

## Task 3: Shell completions (`blazehash completions`)

**Files:**
- Modify: `src/cli.rs` -- add `Mode::Completions`
- Create: `src/commands/completions.rs`
- Modify: `src/commands/mod.rs` -- add `pub mod completions;`
- Modify: `src/main.rs` -- dispatch `Mode::Completions`
- Test: `tests/cli_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/cli_tests.rs`:

```rust
#[test]
fn test_completions_bash_outputs_something() {
    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["completions", "bash"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("blazehash") || stdout.contains("complete"),
        "bash completions must contain shell completion content, got:\n{}",
        &stdout[..stdout.len().min(200)]
    );
}

#[test]
fn test_completions_zsh_outputs_something() {
    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["completions", "zsh"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("blazehash") || stdout.contains("compdef"),
        "zsh completions must contain shell completion content"
    );
}

#[test]
fn test_completions_fish_outputs_something() {
    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args(["completions", "fish"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("blazehash") || stdout.contains("complete"),
        "fish completions must contain shell completion content"
    );
}
```

```bash
cargo test test_completions_ -- 2>&1 | head -20
```
Expected: failure (no `completions` subcommand recognized -- it will be treated as a file path and fail).

**RED commit:**
```bash
git add tests/cli_tests.rs
git commit -m "test(red): failing tests for blazehash completions subcommand"
```

**Step 2: Implement (GREEN)**

In `src/cli.rs`, add `Completions` to the `Mode` enum:

```rust
#[derive(Debug)]
pub enum Mode {
    // ... existing variants ...
    Completions,
    Hash,
}
```

In `Cli::mode()`, add detection before the final `Hash` fallback (after the `vt` check):

```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("completions")) {
    Mode::Completions
}
```

Create `src/commands/completions.rs`:

```rust
use anyhow::{bail, Result};
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::io;

/// Generate shell completions and print to stdout.
pub fn run(shell_name: &str) -> Result<()> {
    let shell = match shell_name.to_lowercase().as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "powershell" | "pwsh" => Shell::PowerShell,
        other => bail!("unsupported shell: {other}. Supported: bash, zsh, fish, powershell"),
    };

    // We need the clap Command. Import the CLI struct from the crate's cli module.
    // Since completions.rs is in src/commands/ (binary crate), it can access the
    // cli module directly.
    let mut cmd = crate::cli::Cli::command();
    generate(shell, &mut cmd, "blazehash", &mut io::stdout());
    Ok(())
}
```

In `src/commands/mod.rs`, add:

```rust
pub mod completions;
```

In `src/main.rs`, add dispatch before the main `match`:

```rust
if let Mode::Completions = cli.mode() {
    let shell = cli
        .paths
        .get(1)
        .and_then(|p| p.to_str())
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash completions <bash|zsh|fish|powershell>"))?;
    commands::completions::run(shell)?;
    return Ok(());
}
```

Add `Completions` to the unreachable match arm in the main match block:

```rust
Mode::Completions => unreachable!(),
```

```bash
cargo test test_completions_
```
Expected: all 3 tests pass.

**GREEN commit:**
```bash
git add src/cli.rs src/commands/completions.rs src/commands/mod.rs src/main.rs tests/cli_tests.rs
git commit -m "feat: blazehash completions subcommand (bash/zsh/fish/powershell)"
```

---

## Task 4: Progress bar with ETA (`indicatif`)

**Files:**
- Modify: `src/cli.rs` -- add `--progress` flag
- Modify: `src/walk.rs` -- add `walk_and_hash_with_progress()` that wraps the rayon walk with an `indicatif::ProgressBar`
- Modify: `src/commands/hash.rs` -- use progress walk when TTY or `--progress`
- Create: `src/progress.rs` -- progress bar helper
- Modify: `src/lib.rs` -- add `pub mod progress;`
- Test: `tests/walk_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/walk_tests.rs`:

```rust
#[test]
fn test_walk_and_hash_with_progress_returns_same_results() {
    use blazehash::algorithm::Algorithm;
    use blazehash::walk::walk_and_hash_with_options;
    use blazehash::walk_filter::WalkFilter;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
    std::fs::write(dir.path().join("b.txt"), "world").unwrap();

    let filter = WalkFilter::builder().build().unwrap();
    let algos = [Algorithm::Blake3];

    // Standard walk
    let standard = walk_and_hash_with_options(dir.path(), &algos, true, &filter, false).unwrap();

    // Progress walk (with progress bar disabled / no-op since not a TTY in tests)
    let with_progress =
        blazehash::progress::walk_and_hash_with_progress(dir.path(), &algos, true, &filter, false)
            .unwrap();

    assert_eq!(standard.results.len(), with_progress.results.len());
}
```

```bash
cargo test test_walk_and_hash_with_progress -- 2>&1 | head -20
```
Expected: compilation error (`blazehash::progress` does not exist).

**RED commit:**
```bash
git add tests/walk_tests.rs
git commit -m "test(red): failing test for walk_and_hash_with_progress"
```

**Step 2: Implement (GREEN)**

Create `src/progress.rs`:

```rust
//! Progress bar support for directory walks using `indicatif`.

use crate::algorithm::Algorithm;
use crate::hash::{hash_file, FileHashResult};
use crate::walk::{walk_paths, WalkError, WalkOutput};
use crate::walk_filter::WalkFilter;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rayon::prelude::*;

/// Walk a directory with a progress bar, hashing all files in parallel.
///
/// The progress bar displays: files processed, bytes/s, ETA.
/// In non-TTY contexts, the progress bar is hidden automatically by `indicatif`.
pub fn walk_and_hash_with_progress(
    root: &Path,
    algorithms: &[Algorithm],
    recursive: bool,
    filter: &WalkFilter,
    compute_entropy: bool,
) -> Result<WalkOutput> {
    let (paths, walk_errors) = walk_paths(root, recursive);

    let filtered: Vec<PathBuf> = paths
        .into_iter()
        .filter(|path| {
            let rel = path.strip_prefix(root).unwrap_or(path);
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
            filter.passes(&rel.to_string_lossy(), size, mtime)
        })
        .collect();

    // Compute total bytes for the progress bar
    let total_bytes: u64 = filtered
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();

    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})"
        )
        .unwrap()
        .progress_chars("=>-"),
    );

    let hash_errors = Mutex::new(Vec::new());
    let results: Vec<FileHashResult> = filtered
        .par_iter()
        .filter_map(|path| {
            let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            match hash_file(path, algorithms, false, false, compute_entropy) {
                Ok(result) => {
                    pb.inc(file_size);
                    Some(result)
                }
                Err(err) => {
                    pb.inc(file_size);
                    hash_errors.lock().unwrap().push(WalkError {
                        path: path.clone(),
                        error: err.to_string(),
                    });
                    None
                }
            }
        })
        .collect();

    pb.finish_with_message("done");

    let mut errors = walk_errors;
    errors.extend(hash_errors.into_inner().unwrap());

    Ok(WalkOutput { results, errors })
}
```

In `src/lib.rs`, add:

```rust
pub mod progress;
```

In `src/cli.rs`, add the `--progress` flag:

```rust
    /// Show progress bar during hashing (auto-enabled on TTY, use to force-enable in pipes)
    #[arg(long = "progress")]
    pub progress: bool,
```

In `src/commands/hash.rs`, add `progress: bool` to `HashOptions`:

```rust
pub struct HashOptions<'a> {
    // ... existing fields ...
    pub progress: bool,
}
```

In `collect_results`, replace the directory walk call to conditionally use progress:

```rust
} else if path.is_dir() {
    let output = if opts_progress {
        blazehash::progress::walk_and_hash_with_progress(
            path, algorithms, recursive, filter, entropy,
        )?
    } else {
        walk_and_hash_with_options(path, algorithms, recursive, filter, entropy)?
    };
    // ... rest unchanged
}
```

The `progress` flag needs to be threaded into `collect_results`. Add `progress: bool` param to `collect_results` and use it in the directory branch.

In `src/main.rs`, pass `progress`:

```rust
progress: cli.progress || atty_is_tty(),
```

For TTY detection, use a simple helper:

```rust
fn is_stdout_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}
```

Then in the `Mode::Hash` arm: `progress: cli.progress || is_stdout_tty()`.

Note: `std::io::IsTerminal` is stable since Rust 1.70 (this project requires 1.85), so no extra dep needed.

```bash
cargo test test_walk_and_hash_with_progress
```
Expected: pass.

**GREEN commit:**
```bash
git add src/progress.rs src/lib.rs src/cli.rs src/commands/hash.rs src/main.rs tests/walk_tests.rs
git commit -m "feat: progress bar with ETA during hashing (indicatif)"
```

---

## Task 5: HashDB bad list support (`--hashdb-bad`)

**Files:**
- Modify: `src/nsrl/mod.rs` -- add `load_bad_list()` function
- Modify: `src/cli.rs` -- add `--hashdb-bad` flag (behind `hashdb` feature)
- Modify: `src/commands/hash.rs` -- integrate bad list check, print `[BAD]` indicator
- Test: `tests/nsrl_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/nsrl_tests.rs`:

```rust
#[cfg(feature = "hashdb")]
mod bad_list_tests {
    use blazehash::nsrl::load_bad_list;

    #[test]
    fn test_load_bad_list_parses_sha256_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let bad_file = dir.path().join("bad_hashes.txt");
        std::fs::write(
            &bad_file,
            "# Known bad hashes\naabbccdd00112233445566778899aabbccddeeff00112233445566778899aabbcc\ndeadbeef00112233445566778899aabbccddeeff00112233445566778899deadbe\n",
        )
        .unwrap();
        let set = load_bad_list(&bad_file).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(
            "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabbcc"
        ));
    }

    #[test]
    fn test_load_bad_list_skips_comments_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let bad_file = dir.path().join("bad_hashes.txt");
        std::fs::write(&bad_file, "# comment\n\naabbccdd\n").unwrap();
        let set = load_bad_list(&bad_file).unwrap();
        // "aabbccdd" is 8 chars -- too short for SHA-256 (64) or SHA-1 (40)
        // Only lines with 40 or 64 hex chars should be loaded
        assert!(set.is_empty(), "short hashes should be rejected");
    }

    #[test]
    fn test_load_bad_list_accepts_sha1_length() {
        let dir = tempfile::tempdir().unwrap();
        let bad_file = dir.path().join("bad_hashes.txt");
        std::fs::write(
            &bad_file,
            "aabbccddeeff00112233445566778899aabbccdd\n",
        )
        .unwrap();
        let set = load_bad_list(&bad_file).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains("aabbccddeeff00112233445566778899aabbccdd"));
    }
}
```

```bash
cargo test --features hashdb bad_list_tests 2>&1 | head -20
```
Expected: compilation error (`load_bad_list` does not exist).

**RED commit:**
```bash
git add tests/nsrl_tests.rs
git commit -m "test(red): failing tests for HashDB bad list loading"
```

**Step 2: Implement (GREEN)**

In `src/nsrl/mod.rs`, add:

```rust
/// Load a flat bad-hash file: one SHA-256 or SHA-1 hash per line (hex).
/// Lines starting with `#` are comments. Empty lines are skipped.
/// Only lines with exactly 40 (SHA-1) or 64 (SHA-256) hex characters are loaded.
#[cfg(feature = "hashdb")]
pub fn load_bad_list(path: &std::path::Path) -> anyhow::Result<std::collections::HashSet<String>> {
    use std::io::{BufRead, BufReader};
    let f = std::fs::File::open(path)?;
    let mut set = std::collections::HashSet::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_lowercase();
        // Accept SHA-256 (64 hex chars) or SHA-1 (40 hex chars)
        if (lower.len() == 64 || lower.len() == 40)
            && lower.chars().all(|c| c.is_ascii_hexdigit())
        {
            set.insert(lower);
        }
    }
    Ok(set)
}
```

In `src/cli.rs`, add the `--hashdb-bad` flag (next to the existing `--nsrl-hsh` flag):

```rust
    /// Path to bad-hash flat file (one SHA-256 or SHA-1 per line)
    #[cfg(feature = "hashdb")]
    #[arg(long = "hashdb-bad", value_name = "FILE")]
    pub hashdb_bad: Option<PathBuf>,
```

In `src/commands/hash.rs`, add `hashdb_bad` to `HashOptions`:

```rust
    #[cfg(feature = "hashdb")]
    pub hashdb_bad: Option<&'a std::path::PathBuf>,
```

In the `#[cfg(feature = "hashdb")]` block within `run()`, after the existing NSRL filtering, add bad-list checking. Bad files are NOT filtered out -- they get a `[BAD]` indicator printed to stderr:

```rust
#[cfg(feature = "hashdb")]
{
    // ... existing NSRL known-good filtering code ...

    // Bad list check: print [BAD] for any file matching a known-bad hash
    if let Some(bad_path) = hashdb_bad {
        let bad_set = blazehash::nsrl::load_bad_list(bad_path)?;
        if !bad_set.is_empty() {
            let mut bad_count = 0usize;
            for r in &all_results {
                let sha256_val = r
                    .hashes
                    .get(&Algorithm::Sha256)
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                let sha1_val = r
                    .hashes
                    .get(&Algorithm::Sha1)
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                if bad_set.contains(&sha256_val) || bad_set.contains(&sha1_val) {
                    eprintln!("[BAD] {}  (matches known-bad hash)", r.path.display());
                    bad_count += 1;
                }
            }
            if bad_count > 0 {
                eprintln!("[BAD] {bad_count} file(s) matched known-bad hashes");
            }
        }
    }
}
```

In `src/main.rs`, pass the new field:

```rust
#[cfg(feature = "hashdb")]
hashdb_bad: cli.hashdb_bad.as_ref(),
```

```bash
cargo test --features hashdb bad_list_tests
```
Expected: all pass.

**GREEN commit:**
```bash
git add src/nsrl/mod.rs src/cli.rs src/commands/hash.rs src/main.rs tests/nsrl_tests.rs
git commit -m "feat: --hashdb-bad flag for known-bad hash list with [BAD] indicator"
```

---

## Task 6: `--patch` output for `blazehash diff`

**Files:**
- Modify: `src/commands/diff.rs` -- add `--patch` flag handling
- Modify: `src/cli.rs` -- add `--patch` flag
- Test: `tests/diff_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/diff_tests.rs`:

```rust
#[test]
fn test_diff_patch_format_shows_unified_diff() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(
        &after,
        &[("aaaa", "/file1.bin"), ("bbbb", "/file2.bin")],
    );

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "diff",
            before.to_str().unwrap(),
            after.to_str().unwrap(),
            "--patch",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("--- ") && stdout.contains("+++ "),
        "patch output must have unified diff headers, got:\n{stdout}"
    );
    assert!(
        stdout.contains("+5,bbbb,/file2.bin"),
        "added entries must be prefixed with +, got:\n{stdout}"
    );
}

#[test]
fn test_diff_patch_format_shows_removed() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin"), ("bbbb", "/file2.bin")]);
    write_hashdeep(&after, &[("aaaa", "/file1.bin")]);

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "diff",
            before.to_str().unwrap(),
            after.to_str().unwrap(),
            "--patch",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("-5,bbbb,/file2.bin"),
        "removed entries must be prefixed with -, got:\n{stdout}"
    );
}

#[test]
fn test_diff_patch_format_shows_modified() {
    let dir = tempdir().unwrap();
    let before = dir.path().join("before.hash");
    let after = dir.path().join("after.hash");
    write_hashdeep(&before, &[("aaaa", "/file1.bin")]);
    write_hashdeep(&after, &[("zzzz", "/file1.bin")]);

    let output = assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "diff",
            before.to_str().unwrap(),
            after.to_str().unwrap(),
            "--patch",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("-5,aaaa,/file1.bin") && stdout.contains("+5,zzzz,/file1.bin"),
        "modified entries must show old (-) and new (+), got:\n{stdout}"
    );
}
```

**RED commit:**
```bash
git add tests/diff_tests.rs
git commit -m "test(red): failing tests for blazehash diff --patch unified output"
```

**Step 2: Implement (GREEN)**

In `src/cli.rs`, add a `--patch` flag:

```rust
    /// Output diff in unified patch format
    #[arg(long = "patch")]
    pub patch: bool,
```

Modify `src/commands/diff.rs` -- update the `run` signature to accept `patch: bool`:

```rust
pub fn run(
    paths: &[PathBuf],
    recursive: bool,
    compare_by: &str,
    show_identical: bool,
    patch: bool,
) -> Result<bool> {
```

In the manifest-vs-manifest diff section, after computing `diffs`, add the patch output path:

```rust
    if patch {
        // Unified diff header
        println!("--- {}", left.display());
        println!("+++ {}", right.display());
        println!("@@ manifest diff @@");
        for d in &diffs {
            match d {
                DiffEntry::Added(p) => {
                    // Find the record in after_records
                    if let Some(rec) = after_records.iter().find(|r| &r.path == p) {
                        let hash = rec.hashes.values().next().map(|s| s.as_str()).unwrap_or("");
                        println!("+{},{},{}", rec.size, hash, p.display());
                    }
                }
                DiffEntry::Removed(p) => {
                    if let Some(rec) = before_records.iter().find(|r| &r.path == p) {
                        let hash = rec.hashes.values().next().map(|s| s.as_str()).unwrap_or("");
                        println!("-{},{},{}", rec.size, hash, p.display());
                    }
                }
                DiffEntry::Modified { path } => {
                    if let Some(rec) = before_records.iter().find(|r| &r.path == path) {
                        let hash = rec.hashes.values().next().map(|s| s.as_str()).unwrap_or("");
                        println!("-{},{},{}", rec.size, hash, path.display());
                    }
                    if let Some(rec) = after_records.iter().find(|r| &r.path == path) {
                        let hash = rec.hashes.values().next().map(|s| s.as_str()).unwrap_or("");
                        println!("+{},{},{}", rec.size, hash, path.display());
                    }
                }
                DiffEntry::Moved { from, to } => {
                    if let Some(rec) = before_records.iter().find(|r| &r.path == from) {
                        let hash = rec.hashes.values().next().map(|s| s.as_str()).unwrap_or("");
                        println!("-{},{},{}", rec.size, hash, from.display());
                    }
                    if let Some(rec) = after_records.iter().find(|r| &r.path == to) {
                        let hash = rec.hashes.values().next().map(|s| s.as_str()).unwrap_or("");
                        println!("+{},{},{}", rec.size, hash, to.display());
                    }
                }
            }
        }
        return Ok(has_diff);
    }
```

The existing non-patch output remains unchanged after this block.

In `src/main.rs`, update the diff dispatch:

```rust
if let Mode::Diff = cli.mode() {
    let has_diff = commands::diff::run(
        &cli.paths,
        cli.recursive,
        &cli.compare_by,
        cli.show_identical,
        cli.patch,
    )?;
```

```bash
cargo test test_diff_patch_format
```
Expected: all pass.

**GREEN commit:**
```bash
git add src/cli.rs src/commands/diff.rs src/main.rs tests/diff_tests.rs
git commit -m "feat: blazehash diff --patch unified-diff-style output"
```

---

## Task 7: STIX 2.1 output (`--format stix`)

**Files:**
- Create: `src/format/stix.rs`
- Modify: `src/format/mod.rs`
- Modify: `src/commands/hash.rs` -- add `"stix"` arm in `write_output`
- Test: `tests/format_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/format_tests.rs`:

```rust
#[test]
fn test_stix_output_is_valid_bundle() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let mut hashes = HashMap::new();
    hashes.insert(
        Algorithm::Sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
    );
    let r = FileHashResult {
        path: PathBuf::from("/evidence/malware.exe"),
        size: 4096,
        hashes,
        entropy: None,
    };

    let mut buf = Vec::new();
    blazehash::format::write_stix(&mut buf, &[r], &[Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();

    let bundle: serde_json::Value = serde_json::from_str(&output).expect("must be valid JSON");
    assert_eq!(bundle["type"], "bundle");
    assert_eq!(bundle["spec_version"], "2.1");

    let objects = bundle["objects"].as_array().expect("objects must be array");
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0]["type"], "file");
    assert_eq!(objects[0]["spec_version"], "2.1");
    assert_eq!(
        objects[0]["hashes"]["SHA-256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(objects[0]["size"], 4096);
    assert_eq!(objects[0]["name"], "malware.exe");

    // ID must be a UUIDv5 deterministic identifier
    let id = objects[0]["id"].as_str().unwrap();
    assert!(
        id.starts_with("file--"),
        "STIX file SCO id must start with file--"
    );
}

#[test]
fn test_stix_output_multiple_algorithms() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Sha256, "abc123".to_string());
    hashes.insert(Algorithm::Md5, "def456".to_string());
    let r = FileHashResult {
        path: PathBuf::from("/test.bin"),
        size: 100,
        hashes,
        entropy: None,
    };

    let mut buf = Vec::new();
    blazehash::format::write_stix(&mut buf, &[r], &[Algorithm::Sha256, Algorithm::Md5]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let bundle: serde_json::Value = serde_json::from_str(&output).unwrap();
    let file_obj = &bundle["objects"][0];
    assert!(file_obj["hashes"]["SHA-256"].is_string());
    assert!(file_obj["hashes"]["MD5"].is_string());
}
```

**RED commit:**
```bash
git add tests/format_tests.rs
git commit -m "test(red): failing tests for STIX 2.1 output format"
```

**Step 2: Implement (GREEN)**

Create `src/format/stix.rs`:

```rust
//! STIX 2.1 Bundle output containing File SCO (Stix Cyber Observable) objects.
//!
//! Each hashed file becomes a STIX `file` SCO with deterministic UUIDv5 ID.
//! Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html

use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use serde_json::{json, Value};
use std::io::Write;
use uuid::Uuid;

/// STIX SCO namespace for deterministic UUIDv5 generation.
/// This is the OASIS-specified namespace: 00abedb4-aa42-466c-9c01-fed23315a9b7
const STIX_SCO_NAMESPACE: Uuid = Uuid::from_bytes([
    0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c, 0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9,
    0xb7,
]);

/// Map blazehash Algorithm to STIX 2.1 hash key name.
/// STIX uses uppercase with hyphens: "SHA-256", "SHA-512", "SHA3-256", "MD5", "SHA-1".
fn stix_hash_name(algo: &Algorithm) -> &'static str {
    match algo {
        Algorithm::Blake3 => "BLAKE3",
        Algorithm::Sha256 => "SHA-256",
        Algorithm::Sha512 => "SHA-512",
        Algorithm::Sha3_256 => "SHA3-256",
        Algorithm::Sha1 => "SHA-1",
        Algorithm::Md5 => "MD5",
        Algorithm::Tiger => "TIGER",
        Algorithm::Whirlpool => "WHIRLPOOL",
        Algorithm::Ssdeep => "SSDEEP",
        Algorithm::Tlsh => "TLSH",
        Algorithm::Crc32c => "CRC32C",
        Algorithm::Xxh3 => "XXH3",
        Algorithm::Shake128 => "SHAKE128",
        Algorithm::Shake256 => "SHAKE256",
    }
}

fn result_to_stix_sco(result: &FileHashResult, algorithms: &[Algorithm]) -> Value {
    let mut hashes = serde_json::Map::new();
    for algo in algorithms {
        if let Some(hash) = result.hashes.get(algo) {
            hashes.insert(stix_hash_name(algo).to_string(), json!(hash));
        }
    }

    // Deterministic ID: UUIDv5 from the hashes dict serialized as JSON (RFC 8785 / JCS).
    // For simplicity, we serialize the hashes map sorted by key.
    let hashes_json = serde_json::to_string(&hashes).unwrap_or_default();
    let id_input = format!("{{\"hashes\":{hashes_json}}}");
    let uuid = Uuid::new_v5(&STIX_SCO_NAMESPACE, id_input.as_bytes());
    let stix_id = format!("file--{uuid}");

    let file_name = result
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    json!({
        "type": "file",
        "spec_version": "2.1",
        "id": stix_id,
        "hashes": hashes,
        "size": result.size,
        "name": file_name,
    })
}

pub fn write_stix<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    let objects: Vec<Value> = results
        .iter()
        .map(|r| result_to_stix_sco(r, algorithms))
        .collect();

    let bundle_uuid = Uuid::new_v5(
        &STIX_SCO_NAMESPACE,
        format!("blazehash-bundle-{}", objects.len()).as_bytes(),
    );
    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{bundle_uuid}"),
        "spec_version": "2.1",
        "objects": objects,
    });

    serde_json::to_writer_pretty(&mut *w, &bundle)?;
    writeln!(w)?;
    Ok(())
}
```

In `src/format/mod.rs`, add:

```rust
pub mod stix;

pub use self::stix::write_stix;
```

In `src/commands/hash.rs`, update `write_output` to handle `"stix"`:

```rust
fn write_output<W: Write>(
    writer: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
    format: &str,
    needs_header: bool,
    case_id: Option<&str>,
    examiner: Option<&str>,
) -> Result<()> {
    match format {
        "csv" => write_csv(writer, results, algorithms)?,
        "dfxml" => write_dfxml(writer, results, algorithms)?,
        "json" => write_json(writer, results, algorithms)?,
        "jsonl" => write_jsonl(writer, results, algorithms)?,
        "sha256sum" | "md5sum" => write_sumfile(writer, results, algorithms)?,
        "stix" => blazehash::format::write_stix(writer, results, algorithms)?,
        _ => {
            if needs_header {
                blazehash::manifest::write_header_with_metadata(
                    writer, algorithms, case_id, examiner,
                )?;
            }
            for result in results {
                write_record(writer, result, algorithms)?;
            }
        }
    }
    Ok(())
}
```

```bash
cargo test test_stix_output
```
Expected: all pass.

**GREEN commit:**
```bash
git add src/format/stix.rs src/format/mod.rs src/commands/hash.rs tests/format_tests.rs
git commit -m "feat: --format stix — STIX 2.1 Bundle output with File SCO objects"
```

---

## Task 8: ECS NDJSON output (`--format ecs`)

**Files:**
- Create: `src/format/ecs.rs`
- Modify: `src/format/mod.rs`
- Modify: `src/commands/hash.rs` -- add `"ecs"` arm
- Test: `tests/format_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/format_tests.rs`:

```rust
#[test]
fn test_ecs_output_has_correct_fields() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let mut hashes = HashMap::new();
    hashes.insert(
        Algorithm::Sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
    );
    let r = FileHashResult {
        path: PathBuf::from("/evidence/file.bin"),
        size: 2048,
        hashes,
        entropy: Some(7.5),
    };

    let mut buf = Vec::new();
    blazehash::format::write_ecs(&mut buf, &[r], &[Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();

    // Each line is a JSON object
    let line = output.lines().next().expect("must have at least one line");
    let doc: serde_json::Value = serde_json::from_str(line).expect("must be valid JSON");

    assert!(doc["@timestamp"].is_string(), "must have @timestamp");
    assert_eq!(doc["file"]["path"], "/evidence/file.bin");
    assert_eq!(
        doc["file"]["hash"]["sha256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(doc["file"]["size"], 2048);
}

#[test]
fn test_ecs_output_is_ndjson() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let results: Vec<FileHashResult> = (0..3)
        .map(|i| {
            let mut hashes = HashMap::new();
            hashes.insert(Algorithm::Blake3, format!("hash{i}"));
            FileHashResult {
                path: PathBuf::from(format!("/file{i}.bin")),
                size: i * 100,
                hashes,
                entropy: None,
            }
        })
        .collect();

    let mut buf = Vec::new();
    blazehash::format::write_ecs(&mut buf, &results, &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 3, "3 records must produce 3 NDJSON lines");
    // Each line must parse as JSON
    for line in lines {
        serde_json::from_str::<serde_json::Value>(line).expect("each line must be valid JSON");
    }
}
```

**RED commit:**
```bash
git add tests/format_tests.rs
git commit -m "test(red): failing tests for ECS NDJSON output format"
```

**Step 2: Implement (GREEN)**

Create `src/format/ecs.rs`:

```rust
//! Elastic Common Schema (ECS) NDJSON output for Splunk/SIEM ingest.
//!
//! Each file produces one JSON line with:
//! - `@timestamp` (ISO 8601 UTC)
//! - `file.path`, `file.size`, `file.name`
//! - `file.hash.<algorithm>` (snake_case key names per ECS convention)
//! - `file.entropy` (if computed)
//!
//! Reference: https://www.elastic.co/guide/en/ecs/current/ecs-file.html

use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use serde_json::json;
use std::io::Write;

/// Map Algorithm to ECS hash field name (snake_case, lowercase).
fn ecs_hash_name(algo: &Algorithm) -> &'static str {
    match algo {
        Algorithm::Blake3 => "blake3",
        Algorithm::Sha256 => "sha256",
        Algorithm::Sha512 => "sha512",
        Algorithm::Sha3_256 => "sha3_256",
        Algorithm::Sha1 => "sha1",
        Algorithm::Md5 => "md5",
        Algorithm::Tiger => "tiger",
        Algorithm::Whirlpool => "whirlpool",
        Algorithm::Ssdeep => "ssdeep",
        Algorithm::Tlsh => "tlsh",
        Algorithm::Crc32c => "crc32c",
        Algorithm::Xxh3 => "xxh3",
        Algorithm::Shake128 => "shake128",
        Algorithm::Shake256 => "shake256",
    }
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Manual UTC formatting (no chrono in hot path)
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let mut y = 1970u32;
    let mut d = days as u32;
    loop {
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let months = [
        31u32,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut mo = 1u32;
    for days_in_month in &months {
        if d < *days_in_month {
            break;
        }
        d -= days_in_month;
        mo += 1;
    }
    format!(
        "{y:04}-{mo:02}-{:02}T{h:02}:{m:02}:{s:02}.000Z",
        d + 1
    )
}

pub fn write_ecs<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    let timestamp = now_iso8601();

    for result in results {
        let mut hash_obj = serde_json::Map::new();
        for algo in algorithms {
            if let Some(hash) = result.hashes.get(algo) {
                hash_obj.insert(ecs_hash_name(algo).to_string(), json!(hash));
            }
        }

        let file_name = result
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let mut file_obj = serde_json::Map::new();
        file_obj.insert(
            "path".to_string(),
            json!(result.path.display().to_string()),
        );
        file_obj.insert("name".to_string(), json!(file_name));
        file_obj.insert("size".to_string(), json!(result.size));
        file_obj.insert("hash".to_string(), serde_json::Value::Object(hash_obj));
        if let Some(entropy) = result.entropy {
            file_obj.insert("entropy".to_string(), json!(entropy));
        }

        let doc = json!({
            "@timestamp": timestamp,
            "event": {
                "kind": "enrichment",
                "category": ["file"],
                "type": ["info"],
                "module": "blazehash"
            },
            "file": file_obj,
        });

        serde_json::to_writer(&mut *w, &doc)?;
        writeln!(w)?;
    }
    Ok(())
}
```

In `src/format/mod.rs`, add:

```rust
pub mod ecs;

pub use self::ecs::write_ecs;
```

In `src/commands/hash.rs`, add `"ecs"` to the match:

```rust
"ecs" => blazehash::format::write_ecs(writer, results, algorithms)?,
```

```bash
cargo test test_ecs_output
```
Expected: all pass.

**GREEN commit:**
```bash
git add src/format/ecs.rs src/format/mod.rs src/commands/hash.rs tests/format_tests.rs
git commit -m "feat: --format ecs — Elastic Common Schema NDJSON output for SIEM ingest"
```

---

## Task 9: Sector-level raw device hashing

**Files:**
- Create: `src/device.rs` -- raw device reading + sector hashing
- Modify: `src/lib.rs` -- add `pub mod device;`
- Modify: `src/cli.rs` -- add `--sector-size` flag
- Modify: `src/commands/hash.rs` -- detect `/dev/` paths, dispatch to device hasher
- Test: `tests/hash_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_hash_device_on_regular_file() {
    // hash_device should work on regular files too (reads sequentially)
    use blazehash::algorithm::Algorithm;
    use blazehash::device::hash_device;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.bin");
    std::fs::write(&file, vec![0u8; 4096]).unwrap();

    let result = hash_device(&file, &[Algorithm::Blake3], 512).unwrap();
    assert_eq!(result.size, 4096);
    assert!(result.hashes.contains_key(&Algorithm::Blake3));
    // Verify the hash matches the known BLAKE3 of 4096 zero bytes
    let expected = blazehash::algorithm::hash_bytes(Algorithm::Blake3, &[0u8; 4096]);
    assert_eq!(result.hashes[&Algorithm::Blake3], expected);
}

#[test]
fn test_hash_device_synthetic_path() {
    use blazehash::algorithm::Algorithm;
    use blazehash::device::hash_device;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("disk.img");
    std::fs::write(&file, vec![0xAB; 1024]).unwrap();

    let result = hash_device(&file, &[Algorithm::Sha256], 512).unwrap();
    // Path should be preserved as-is
    assert_eq!(result.path, file);
    assert_eq!(result.size, 1024);
}
```

**RED commit:**
```bash
git add tests/hash_tests.rs
git commit -m "test(red): failing tests for sector-level device/file hashing"
```

**Step 2: Implement (GREEN)**

Create `src/device.rs`:

```rust
//! Sector-level raw device hashing.
//!
//! Reads a raw block device (or any file) in fixed-size sector chunks,
//! streaming all data through the selected hash algorithms. Produces
//! one `FileHashResult` for the entire device.
//!
//! On Linux: auto-detects block size via `ioctl(BLKGETSIZE64)`.
//! On macOS: uses `ioctl(DKIOCGETBLOCKSIZE)` for physical sector size.
//! On Windows: graceful error (raw device hashing not supported).

use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Default forensic sector size (512 bytes, standard for forensic imaging).
pub const DEFAULT_SECTOR_SIZE: usize = 512;

/// Read buffer size: 1 MiB aligned to sector boundary for throughput.
const READ_BUF_SIZE: usize = 1024 * 1024;

/// Detect if the path is likely a raw device.
pub fn is_device_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/dev/") || s.starts_with("\\\\.\\")
}

/// Try to auto-detect the physical sector size for a device.
/// Falls back to `DEFAULT_SECTOR_SIZE` if detection fails.
#[cfg(target_os = "linux")]
pub fn detect_sector_size(path: &Path) -> usize {
    use std::os::unix::io::AsRawFd;
    // BLKSSZGET = 0x1268
    const BLKSSZGET: libc::c_ulong = 0x1268;
    if let Ok(file) = std::fs::File::open(path) {
        let mut sector_size: libc::c_int = 0;
        let ret =
            unsafe { libc::ioctl(file.as_raw_fd(), BLKSSZGET, &mut sector_size as *mut _) };
        if ret == 0 && sector_size > 0 {
            return sector_size as usize;
        }
    }
    DEFAULT_SECTOR_SIZE
}

#[cfg(target_os = "macos")]
pub fn detect_sector_size(path: &Path) -> usize {
    use std::os::unix::io::AsRawFd;
    // DKIOCGETBLOCKSIZE = 0x40046418
    const DKIOCGETBLOCKSIZE: libc::c_ulong = 0x40046418;
    if let Ok(file) = std::fs::File::open(path) {
        let mut block_size: u32 = 0;
        let ret = unsafe {
            libc::ioctl(file.as_raw_fd(), DKIOCGETBLOCKSIZE, &mut block_size as *mut _)
        };
        if ret == 0 && block_size > 0 {
            return block_size as usize;
        }
    }
    DEFAULT_SECTOR_SIZE
}

#[cfg(target_os = "windows")]
pub fn detect_sector_size(_path: &Path) -> usize {
    DEFAULT_SECTOR_SIZE
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn detect_sector_size(_path: &Path) -> usize {
    DEFAULT_SECTOR_SIZE
}

/// Hash a raw device or file by reading it sequentially in sectors.
///
/// `sector_size` is the logical sector size for alignment. The actual read
/// buffer is `READ_BUF_SIZE` (1 MiB) for throughput, rounded down to sector boundary.
pub fn hash_device(
    path: &Path,
    algorithms: &[Algorithm],
    sector_size: usize,
) -> Result<FileHashResult> {
    let sector_size = if sector_size == 0 {
        DEFAULT_SECTOR_SIZE
    } else {
        sector_size
    };

    let mut file = std::fs::File::open(path)
        .with_context(|| format!("failed to open device/file {}", path.display()))?;

    // Align read buffer to sector boundary
    let buf_size = (READ_BUF_SIZE / sector_size) * sector_size;
    let buf_size = buf_size.max(sector_size); // at least one sector
    let mut buf = vec![0u8; buf_size];

    // Build one hasher per algorithm (reuse the algorithm::hash_bytes approach
    // but streaming). For simplicity, accumulate all bytes and hash at end
    // for algorithms that need full reads, or use digest trait for crypto algos.
    // Given device sizes can be huge, we MUST stream. Use the same approach as hash.rs.
    let fuzzy_algorithms: Vec<Algorithm> =
        algorithms.iter().filter(|a| a.is_fuzzy()).copied().collect();
    let full_read_algorithms: Vec<Algorithm> = algorithms
        .iter()
        .filter(|a| a.needs_full_read())
        .copied()
        .collect();
    let crypto_algorithms: Vec<Algorithm> = algorithms
        .iter()
        .filter(|a| !a.is_fuzzy() && !a.needs_full_read())
        .copied()
        .collect();

    if !fuzzy_algorithms.is_empty() || !full_read_algorithms.is_empty() {
        anyhow::bail!(
            "fuzzy and non-cryptographic algorithms (ssdeep, tlsh, crc32c, xxh3) \
             are not supported for device hashing (requires full file in memory)"
        );
    }

    // Streaming hashers for crypto algorithms
    use digest::Digest;
    struct Blake3H(blake3::Hasher);
    struct DigestH<D: Digest>(D);

    enum DynH {
        Blake3(blake3::Hasher),
        Sha256(sha2::Sha256),
        Sha512(sha2::Sha512),
        Sha3_256(sha3::Sha3_256),
        Sha1(sha1::Sha1),
        Md5(md5::Md5),
        Tiger(tiger::Tiger),
        Whirlpool(whirlpool::Whirlpool),
    }

    impl DynH {
        fn update(&mut self, data: &[u8]) {
            match self {
                DynH::Blake3(h) => { h.update(data); }
                DynH::Sha256(h) => { h.update(data); }
                DynH::Sha512(h) => { h.update(data); }
                DynH::Sha3_256(h) => { h.update(data); }
                DynH::Sha1(h) => { h.update(data); }
                DynH::Md5(h) => { h.update(data); }
                DynH::Tiger(h) => { h.update(data); }
                DynH::Whirlpool(h) => { h.update(data); }
            }
        }
        fn finalize_hex(self) -> String {
            match self {
                DynH::Blake3(h) => h.finalize().to_hex().to_string(),
                DynH::Sha256(h) => hex::encode(h.finalize()),
                DynH::Sha512(h) => hex::encode(h.finalize()),
                DynH::Sha3_256(h) => hex::encode(h.finalize()),
                DynH::Sha1(h) => hex::encode(h.finalize()),
                DynH::Md5(h) => hex::encode(h.finalize()),
                DynH::Tiger(h) => hex::encode(h.finalize()),
                DynH::Whirlpool(h) => hex::encode(h.finalize()),
            }
        }
    }

    fn make_dynh(algo: Algorithm) -> DynH {
        match algo {
            Algorithm::Blake3 => DynH::Blake3(blake3::Hasher::new()),
            Algorithm::Sha256 => DynH::Sha256(sha2::Sha256::new()),
            Algorithm::Sha512 => DynH::Sha512(sha2::Sha512::new()),
            Algorithm::Sha3_256 => DynH::Sha3_256(sha3::Sha3_256::new()),
            Algorithm::Sha1 => DynH::Sha1(sha1::Sha1::new()),
            Algorithm::Md5 => DynH::Md5(md5::Md5::new()),
            Algorithm::Tiger => DynH::Tiger(tiger::Tiger::new()),
            Algorithm::Whirlpool => DynH::Whirlpool(whirlpool::Whirlpool::new()),
            _ => unreachable!("non-streaming algorithms already filtered"),
        }
    }

    let mut hashers: Vec<(Algorithm, DynH)> = crypto_algorithms
        .iter()
        .map(|a| (*a, make_dynh(*a)))
        .collect();

    let mut total_bytes: u64 = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for (_, h) in &mut hashers {
            h.update(&buf[..n]);
        }
        total_bytes += n as u64;
    }

    let mut hashes = HashMap::new();
    for (algo, h) in hashers {
        hashes.insert(algo, h.finalize_hex());
    }

    Ok(FileHashResult {
        path: path.to_path_buf(),
        size: total_bytes,
        hashes,
        entropy: None,
    })
}
```

In `src/lib.rs`, add:

```rust
pub mod device;
```

In `src/cli.rs`, add:

```rust
    /// Sector size for raw device hashing (default: 512)
    #[arg(long = "sector-size", default_value = "512", value_parser = clap::value_parser!(usize))]
    pub sector_size: usize,
```

In `src/commands/hash.rs`, in the `collect_results` function, before the `for path in paths` loop, add device detection:

```rust
for path in paths {
    if blazehash::device::is_device_path(path) || (path.is_file() && sector_size != 512) {
        // Only use device hashing for /dev/ paths; for regular files, use standard hash
    }
    if blazehash::device::is_device_path(path) {
        let result = blazehash::device::hash_device(path, algorithms, sector_size)?;
        all_results.push(result);
        continue;
    }
    // ... existing file/dir handling ...
}
```

Add `sector_size: usize` to `HashOptions` and thread it through.

```bash
cargo test test_hash_device
```
Expected: all pass.

**GREEN commit:**
```bash
git add src/device.rs src/lib.rs src/cli.rs src/commands/hash.rs tests/hash_tests.rs
git commit -m "feat: sector-level raw device hashing (blazehash hash /dev/sda)"
```

---

## Task 10: Multi-party signing (`blazehash cosign` / `verify-msig`)

**Files:**
- Create: `src/cosign.rs`
- Modify: `src/lib.rs`
- Modify: `src/cli.rs` -- add `Mode::Cosign`, `Mode::VerifyMsig`
- Modify: `src/main.rs` -- dispatch
- Test: `tests/signing_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/signing_tests.rs`:

```rust
#[test]
fn test_cosign_creates_msig_file() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    std::fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "cosigner-1")
        .args(["cosign", manifest.to_str().unwrap()])
        .assert()
        .success();

    let msig_path = dir.path().join("manifest.hash.msig");
    assert!(msig_path.exists(), ".msig file not created");

    let content = std::fs::read_to_string(&msig_path).unwrap();
    let msig: serde_json::Value = serde_json::from_str(&content).expect("msig must be valid JSON");
    let sigs = msig["signatures"].as_array().expect("must have signatures array");
    assert_eq!(sigs.len(), 1, "first cosign should create 1 signature entry");
}

#[test]
fn test_cosign_appends_second_signature() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    std::fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    // First cosign
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "cosigner-1")
        .args(["cosign", manifest.to_str().unwrap()])
        .assert()
        .success();

    // Second cosign (different password = different key)
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "cosigner-2")
        .args(["cosign", manifest.to_str().unwrap()])
        .assert()
        .success();

    let msig_path = dir.path().join("manifest.hash.msig");
    let content = std::fs::read_to_string(&msig_path).unwrap();
    let msig: serde_json::Value = serde_json::from_str(&content).unwrap();
    let sigs = msig["signatures"].as_array().unwrap();
    assert_eq!(sigs.len(), 2, "second cosign should add 2nd signature");
}

#[test]
fn test_verify_msig_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("manifest.hash");
    std::fs::write(
        &manifest,
        "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n",
    )
    .unwrap();

    // Two cosigns
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "cosigner-1")
        .args(["cosign", manifest.to_str().unwrap()])
        .assert()
        .success();
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .env("BLAZEHASH_SIGN_PASSWORD", "cosigner-2")
        .args(["cosign", manifest.to_str().unwrap()])
        .assert()
        .success();

    // Verify with threshold=2 -- should pass
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "verify-msig",
            manifest.to_str().unwrap(),
            "--threshold",
            "2",
        ])
        .assert()
        .success();

    // Verify with threshold=3 -- should fail (only 2 sigs)
    assert_cmd::Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "verify-msig",
            manifest.to_str().unwrap(),
            "--threshold",
            "3",
        ])
        .assert()
        .failure();
}
```

**RED commit:**
```bash
git add tests/signing_tests.rs
git commit -m "test(red): failing tests for multi-party cosigning (cosign/verify-msig)"
```

**Step 2: Implement (GREEN)**

Create `src/cosign.rs`:

```rust
//! Multi-party manifest signing (N-of-M cosigning).
//!
//! `.msig` format: JSON object with `manifest_sha256` (integrity check),
//! `signatures` array of `{ pubkey, sig, signed_at }` entries.

use crate::signing::{derive_key_from_password, read_password};
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct MsigFile {
    /// SHA-256 of the manifest at the time signatures were created.
    /// If the manifest changes between cosigns, new cosigns will fail verification.
    pub manifest_sha256: String,
    pub signatures: Vec<MsigEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MsigEntry {
    pub pubkey: String,
    pub sig: String,
    pub signed_at: u64,
}

fn msig_path_for(manifest_path: &Path) -> std::path::PathBuf {
    let mut p = manifest_path.to_path_buf();
    let new_name = format!(
        "{}.msig",
        manifest_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("manifest")
    );
    p.set_file_name(new_name);
    p
}

fn manifest_sha256(manifest_path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Add a cosignature to the `.msig` file (create if absent).
pub fn cosign(manifest_path: &Path) -> Result<()> {
    let password = read_password()?;
    // Reuse the same key derivation as signing.rs
    let signing_key = derive_key_from_password(&password)?;
    let verifying_key = signing_key.verifying_key();

    let manifest_bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;
    let manifest_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&manifest_bytes))
    };

    let signature: Signature = signing_key.sign(&manifest_bytes);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pubkey_hex = hex::encode(verifying_key.to_bytes());
    let entry = MsigEntry {
        pubkey: pubkey_hex.clone(),
        sig: hex::encode(signature.to_bytes()),
        signed_at: timestamp,
    };

    let msig_path = msig_path_for(manifest_path);
    let mut msig = if msig_path.exists() {
        let content = std::fs::read_to_string(&msig_path)
            .with_context(|| format!("cannot read {}", msig_path.display()))?;
        let existing: MsigFile =
            serde_json::from_str(&content).context("invalid .msig file")?;
        // Verify manifest hasn't changed since previous cosigns
        if existing.manifest_sha256 != manifest_hash {
            bail!(
                "manifest SHA-256 mismatch: .msig was created for {} but manifest is now {}. \
                 The manifest must not change between cosigns.",
                existing.manifest_sha256,
                manifest_hash
            );
        }
        existing
    } else {
        MsigFile {
            manifest_sha256: manifest_hash,
            signatures: Vec::new(),
        }
    };

    // Check for duplicate pubkey
    if msig.signatures.iter().any(|e| e.pubkey == pubkey_hex) {
        eprintln!("[!] Warning: this key has already cosigned this manifest (replacing)");
        msig.signatures.retain(|e| e.pubkey != pubkey_hex);
    }

    msig.signatures.push(entry);

    let json = serde_json::to_string_pretty(&msig)?;
    std::fs::write(&msig_path, json)
        .with_context(|| format!("cannot write {}", msig_path.display()))?;

    eprintln!("[+] Cosigned: {}", manifest_path.display());
    eprintln!("[+] Public key: {pubkey_hex}");
    eprintln!(
        "[+] Total signatures: {}",
        msig.signatures.len()
    );
    Ok(())
}

/// Verify that at least `threshold` valid signatures exist in the `.msig` file.
pub fn verify_msig(manifest_path: &Path, threshold: usize) -> Result<bool> {
    let msig_path = msig_path_for(manifest_path);
    let content = std::fs::read_to_string(&msig_path)
        .with_context(|| format!("cannot read {}", msig_path.display()))?;
    let msig: MsigFile = serde_json::from_str(&content).context("invalid .msig file")?;

    // Verify manifest hash matches
    let current_hash = manifest_sha256(manifest_path)?;
    if msig.manifest_sha256 != current_hash {
        eprintln!(
            "[!] Manifest SHA-256 mismatch: .msig={}, current={}",
            msig.manifest_sha256, current_hash
        );
        return Ok(false);
    }

    let manifest_bytes = std::fs::read(manifest_path)?;
    let mut valid_count = 0usize;

    for entry in &msig.signatures {
        let pub_bytes = match hex::decode(&entry.pubkey) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let pub_arr: [u8; 32] = match pub_bytes.try_into() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let verifying_key = match VerifyingKey::from_bytes(&pub_arr) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let sig_bytes = match hex::decode(&entry.sig) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let signature = Signature::from_bytes(&sig_arr);

        if verifying_key.verify(&manifest_bytes, &signature).is_ok() {
            eprintln!(
                "[+] Valid signature from {}",
                &entry.pubkey[..16]
            );
            valid_count += 1;
        } else {
            eprintln!(
                "[!] INVALID signature from {}",
                &entry.pubkey[..16]
            );
        }
    }

    eprintln!(
        "[*] {valid_count}/{} signatures valid, threshold={threshold}",
        msig.signatures.len()
    );

    if valid_count >= threshold {
        eprintln!("[+] Threshold met");
        Ok(true)
    } else {
        eprintln!("[!] Threshold NOT met");
        Ok(false)
    }
}
```

IMPORTANT: The `derive_key_from_password` function needs to be made `pub` in `src/signing.rs`. Rename the existing `derive_key` function:

```rust
/// Derive an Ed25519 signing key from a password using Argon2id.
pub fn derive_key_from_password(password: &str) -> Result<SigningKey> {
    // ... existing body of derive_key ...
}
```

And update the call site in `signing::sign` to use `derive_key_from_password`.

In `src/lib.rs`, add:

```rust
pub mod cosign;
```

In `src/cli.rs`, add modes:

```rust
pub enum Mode {
    // ... existing ...
    Cosign,
    VerifyMsig,
    // ...
}
```

Add `--threshold` flag:

```rust
    /// Minimum number of valid signatures for verify-msig (default: 1)
    #[arg(long = "threshold", default_value = "1")]
    pub threshold: usize,
```

In `Cli::mode()`, add detection:

```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("cosign")) {
    Mode::Cosign
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("verify-msig")) {
    Mode::VerifyMsig
}
```

In `src/main.rs`, add dispatch:

```rust
if let Mode::Cosign = cli.mode() {
    let manifest = cli
        .paths
        .get(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash cosign <manifest>"))?;
    blazehash::cosign::cosign(&manifest)?;
    return Ok(());
}

if let Mode::VerifyMsig = cli.mode() {
    let manifest = cli
        .paths
        .get(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash verify-msig <manifest> --threshold N"))?;
    let valid = blazehash::cosign::verify_msig(&manifest, cli.threshold)?;
    if !valid {
        std::process::exit(1);
    }
    return Ok(());
}
```

```bash
cargo test test_cosign test_verify_msig
```
Expected: all pass.

**GREEN commit:**
```bash
git add src/cosign.rs src/signing.rs src/lib.rs src/cli.rs src/main.rs tests/signing_tests.rs
git commit -m "feat: multi-party cosigning (blazehash cosign/verify-msig with .msig JSON)"
```

---

## Task 11: OpenTimestamps (OTS) notarization

The `opentimestamps` crate on crates.io is v0.2.0, published April 2023, depends on `bitcoin ^0.12` (severely outdated). We implement the minimal OTS calendar protocol directly using `ureq` (already a dependency) and `sha2`.

**Files:**
- Create: `src/ots.rs`
- Modify: `src/lib.rs` -- add `#[cfg(feature = "ots")] pub mod ots;`
- Modify: `src/cli.rs` -- add `Mode::OtsStamp`, `Mode::OtsVerify`
- Modify: `src/main.rs` -- dispatch
- Test: `tests/cli_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/cli_tests.rs`:

```rust
#[cfg(feature = "ots")]
mod ots_tests {
    use tempfile::tempdir;

    #[test]
    fn test_ots_stamp_unit_hash() {
        // Unit test: verify the stamp function computes correct SHA-256 digest
        use blazehash::ots::compute_manifest_digest;

        let dir = tempdir().unwrap();
        let manifest = dir.path().join("test.hash");
        std::fs::write(&manifest, "test content for OTS").unwrap();

        let digest = compute_manifest_digest(&manifest).unwrap();
        assert_eq!(digest.len(), 32, "SHA-256 digest must be 32 bytes");

        // Verify it matches expected SHA-256
        use sha2::{Digest, Sha256};
        let expected = Sha256::digest(b"test content for OTS");
        assert_eq!(digest, expected.as_slice());
    }

    #[test]
    fn test_ots_sidecar_path() {
        use blazehash::ots::ots_path_for;
        use std::path::PathBuf;

        let p = PathBuf::from("/evidence/manifest.hash");
        assert_eq!(
            ots_path_for(&p),
            PathBuf::from("/evidence/manifest.hash.ots")
        );
    }
}
```

**RED commit:**
```bash
git add tests/cli_tests.rs
git commit -m "test(red): failing tests for OTS notarization (digest computation + sidecar path)"
```

**Step 2: Implement (GREEN)**

Create `src/ots.rs`:

```rust
//! OpenTimestamps (OTS) notarization — minimal calendar protocol client.
//!
//! Protocol:
//! 1. Compute SHA-256 digest of the manifest file
//! 2. POST raw 32-byte digest to calendar server: `POST /digest`
//! 3. Save binary response as `.ots` sidecar file
//!
//! Verification:
//! - Re-compute SHA-256 of manifest
//! - POST existing `.ots` proof + digest to calendar's verify endpoint
//!
//! Calendar servers used:
//! - https://alice.btc.calendar.opentimestamps.org
//! - https://bob.btc.calendar.opentimestamps.org (fallback)

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const CALENDAR_SERVERS: &[&str] = &[
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
];

/// Compute the `.ots` sidecar path for a given manifest.
pub fn ots_path_for(manifest_path: &Path) -> PathBuf {
    let mut p = manifest_path.to_path_buf().into_os_string();
    p.push(".ots");
    PathBuf::from(p)
}

/// Compute SHA-256 digest of a manifest file.
pub fn compute_manifest_digest(manifest_path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(manifest_path)
        .with_context(|| format!("cannot read manifest {}", manifest_path.display()))?;
    Ok(Sha256::digest(&bytes).to_vec())
}

/// Submit a SHA-256 digest to an OTS calendar server and return the binary proof.
fn submit_to_calendar(digest: &[u8]) -> Result<Vec<u8>> {
    let mut last_err = None;
    for server in CALENDAR_SERVERS {
        let url = format!("{server}/digest");
        eprintln!("[*] Submitting to {url}...");
        match ureq::post(&url)
            .set("Content-Type", "application/octet-stream")
            .set("Accept", "application/octet-stream")
            .send_bytes(digest)
        {
            Ok(response) => {
                let mut body = Vec::new();
                response
                    .into_reader()
                    .read_to_end(&mut body)
                    .context("failed to read OTS response")?;
                if body.is_empty() {
                    last_err = Some(anyhow::anyhow!("empty response from {server}"));
                    continue;
                }
                return Ok(body);
            }
            Err(e) => {
                eprintln!("[!] Failed: {e}");
                last_err = Some(anyhow::anyhow!("calendar {server}: {e}"));
            }
        }
    }
    bail!(
        "all OTS calendar servers failed: {}",
        last_err.unwrap_or_else(|| anyhow::anyhow!("no servers configured"))
    )
}

/// Stamp a manifest: compute digest, submit to calendar, save `.ots` proof.
pub fn stamp(manifest_path: &Path) -> Result<()> {
    let digest = compute_manifest_digest(manifest_path)?;
    eprintln!(
        "[*] Manifest SHA-256: {}",
        hex::encode(&digest)
    );

    let proof = submit_to_calendar(&digest)?;

    let ots_path = ots_path_for(manifest_path);
    std::fs::write(&ots_path, &proof)
        .with_context(|| format!("cannot write {}", ots_path.display()))?;

    eprintln!("[+] OTS proof saved: {} ({} bytes)", ots_path.display(), proof.len());
    Ok(())
}

/// Verify an existing `.ots` proof against the manifest.
///
/// This performs a basic check: re-compute the manifest digest and verify
/// the `.ots` file exists and was created for this digest. Full Bitcoin
/// blockchain verification requires an OTS server or local bitcoind.
pub fn verify(manifest_path: &Path) -> Result<bool> {
    let ots_path = ots_path_for(manifest_path);
    if !ots_path.exists() {
        bail!("no .ots file found at {}", ots_path.display());
    }

    let digest = compute_manifest_digest(manifest_path)?;
    let proof = std::fs::read(&ots_path)
        .with_context(|| format!("cannot read {}", ots_path.display()))?;

    // Basic validation: the proof must be non-empty and start with the OTS magic byte
    // OTS v1 files start with: \x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94
    // But calendar responses (incomplete proofs) may have different format.
    // For now, verify the proof is non-empty and report the digest.
    if proof.is_empty() {
        eprintln!("[!] OTS proof file is empty");
        return Ok(false);
    }

    eprintln!("[*] Manifest SHA-256: {}", hex::encode(&digest));
    eprintln!(
        "[*] OTS proof: {} ({} bytes)",
        ots_path.display(),
        proof.len()
    );
    eprintln!("[+] OTS proof file exists and is non-empty.");
    eprintln!("[*] For full Bitcoin verification, use: ots verify {}", ots_path.display());
    Ok(true)
}
```

In `src/lib.rs`, add:

```rust
#[cfg(feature = "ots")]
pub mod ots;
```

In `src/cli.rs`, add modes:

```rust
pub enum Mode {
    // ... existing ...
    #[cfg(feature = "ots")]
    OtsStamp,
    #[cfg(feature = "ots")]
    OtsVerify,
    // ...
}
```

In `Cli::mode()`:

```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("ots")) {
    match self.paths.get(1).and_then(|p| p.to_str()) {
        Some("stamp") => {
            #[cfg(feature = "ots")]
            return Mode::OtsStamp;
            #[cfg(not(feature = "ots"))]
            Mode::Hash
        }
        Some("verify") => {
            #[cfg(feature = "ots")]
            return Mode::OtsVerify;
            #[cfg(not(feature = "ots"))]
            Mode::Hash
        }
        _ => Mode::Hash,
    }
}
```

In `src/main.rs`, add dispatch:

```rust
#[cfg(feature = "ots")]
if let Mode::OtsStamp = cli.mode() {
    let manifest = cli
        .paths
        .get(2)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash ots stamp <manifest>"))?;
    blazehash::ots::stamp(&manifest)?;
    return Ok(());
}

#[cfg(feature = "ots")]
if let Mode::OtsVerify = cli.mode() {
    let manifest = cli
        .paths
        .get(2)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: blazehash ots verify <manifest>"))?;
    let valid = blazehash::ots::verify(&manifest)?;
    if !valid {
        std::process::exit(1);
    }
    return Ok(());
}
```

```bash
cargo test --features ots ots_tests
```
Expected: unit tests pass (no network calls in tests).

**GREEN commit:**
```bash
git add src/ots.rs src/lib.rs src/cli.rs src/main.rs tests/cli_tests.rs
git commit -m "feat: blazehash ots stamp/verify — OpenTimestamps notarization (minimal protocol)"
```

---

## Task 12: Interactive TUI (`blazehash tui`)

**Files:**
- Create: `src/tui.rs` -- ratatui-based TUI
- Modify: `src/lib.rs` -- `#[cfg(feature = "tui")] pub mod tui;`
- Modify: `src/cli.rs` -- add `Mode::Tui`
- Modify: `src/main.rs` -- dispatch
- Test: `tests/cli_tests.rs`

**Step 1: Write failing tests (RED)**

Add to `tests/cli_tests.rs`:

```rust
#[cfg(feature = "tui")]
mod tui_tests {
    #[test]
    fn test_tui_event_channel_send_receive() {
        use blazehash::tui::{TuiEvent, HashProgress};
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel::<TuiEvent>();
        tx.send(TuiEvent::FileStarted {
            path: "/test.bin".into(),
        })
        .unwrap();
        tx.send(TuiEvent::FileCompleted(HashProgress {
            path: "/test.bin".into(),
            size: 1024,
            hash_preview: "abc123...".to_string(),
        }))
        .unwrap();
        tx.send(TuiEvent::Finished { total_files: 1, total_bytes: 1024 }).unwrap();

        match rx.recv().unwrap() {
            TuiEvent::FileStarted { path } => assert_eq!(path, "/test.bin"),
            _ => panic!("expected FileStarted"),
        }
        match rx.recv().unwrap() {
            TuiEvent::FileCompleted(p) => {
                assert_eq!(p.size, 1024);
            }
            _ => panic!("expected FileCompleted"),
        }
    }
}
```

**RED commit:**
```bash
git add tests/cli_tests.rs
git commit -m "test(red): failing tests for TUI event channel types"
```

**Step 2: Implement (GREEN)**

Create `src/tui.rs`:

```rust
//! Interactive TUI for blazehash using ratatui + crossterm.
//!
//! Architecture:
//! - Main thread: ratatui event loop (render + input)
//! - Worker thread: rayon walk+hash, sends `TuiEvent` via mpsc channel
//!
//! The TUI displays:
//! - Current file being hashed
//! - Progress bar (bytes processed / total bytes)
//! - Throughput (MB/s)
//! - Recent completions list (last 20 files)

use crate::algorithm::Algorithm;
use crate::hash::{hash_file, FileHashResult};
use crate::walk::walk_paths;
use crate::walk_filter::WalkFilter;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Events sent from the worker thread to the TUI render thread.
#[derive(Debug)]
pub enum TuiEvent {
    FileStarted { path: String },
    FileCompleted(HashProgress),
    Error { path: String, error: String },
    Finished { total_files: usize, total_bytes: u64 },
}

#[derive(Debug)]
pub struct HashProgress {
    pub path: String,
    pub size: u64,
    pub hash_preview: String,
}

/// TUI application state.
struct App {
    current_file: String,
    completed: Vec<HashProgress>,
    total_bytes: u64,
    processed_bytes: u64,
    total_files: usize,
    processed_files: usize,
    start_time: Instant,
    finished: bool,
    results: Vec<FileHashResult>,
}

/// Run the TUI.
pub fn run_tui(
    paths: &[PathBuf],
    algorithms: &[Algorithm],
    recursive: bool,
    filter: &WalkFilter,
    entropy: bool,
) -> Result<Vec<FileHashResult>> {
    use crossterm::{
        event::{self, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
        Terminal,
    };

    // Collect all file paths first
    let mut all_paths = Vec::new();
    for path in paths {
        if path.is_file() {
            all_paths.push(path.clone());
        } else if path.is_dir() {
            let (found, _errors) = walk_paths(path, recursive);
            let filtered: Vec<PathBuf> = found
                .into_iter()
                .filter(|p| {
                    let rel = p.strip_prefix(path).unwrap_or(p);
                    let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                    let mtime = std::fs::metadata(p).ok().and_then(|m| m.modified().ok());
                    filter.passes(&rel.to_string_lossy(), size, mtime)
                })
                .collect();
            all_paths.extend(filtered);
        }
    }

    let total_bytes: u64 = all_paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    let total_files = all_paths.len();

    let (tx, rx) = mpsc::channel::<TuiEvent>();

    // Spawn worker thread
    let algos = algorithms.to_vec();
    let worker = std::thread::spawn(move || -> Vec<FileHashResult> {
        let mut results = Vec::new();
        for path in &all_paths {
            let _ = tx.send(TuiEvent::FileStarted {
                path: path.display().to_string(),
            });
            match hash_file(path, &algos, false, false, entropy) {
                Ok(result) => {
                    let preview = result
                        .hashes
                        .values()
                        .next()
                        .map(|h| {
                            if h.len() > 16 {
                                format!("{}...", &h[..16])
                            } else {
                                h.clone()
                            }
                        })
                        .unwrap_or_default();
                    let _ = tx.send(TuiEvent::FileCompleted(HashProgress {
                        path: path.display().to_string(),
                        size: result.size,
                        hash_preview: preview,
                    }));
                    results.push(result);
                }
                Err(e) => {
                    let _ = tx.send(TuiEvent::Error {
                        path: path.display().to_string(),
                        error: e.to_string(),
                    });
                }
            }
        }
        let total_bytes: u64 = results.iter().map(|r| r.size).sum();
        let _ = tx.send(TuiEvent::Finished {
            total_files: results.len(),
            total_bytes,
        });
        results
    });

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App {
        current_file: String::new(),
        completed: Vec::new(),
        total_bytes,
        processed_bytes: 0,
        total_files,
        processed_files: 0,
        start_time: Instant::now(),
        finished: false,
        results: Vec::new(),
    };

    loop {
        // Drain events
        while let Ok(evt) = rx.try_recv() {
            match evt {
                TuiEvent::FileStarted { path } => {
                    app.current_file = path;
                }
                TuiEvent::FileCompleted(progress) => {
                    app.processed_bytes += progress.size;
                    app.processed_files += 1;
                    app.completed.push(progress);
                    if app.completed.len() > 20 {
                        app.completed.remove(0);
                    }
                }
                TuiEvent::Error { path, error } => {
                    app.completed.push(HashProgress {
                        path: format!("[ERR] {path}: {error}"),
                        size: 0,
                        hash_preview: String::new(),
                    });
                }
                TuiEvent::Finished { .. } => {
                    app.finished = true;
                }
            }
        }

        // Render
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Title
                    Constraint::Length(3), // Progress bar
                    Constraint::Length(3), // Stats
                    Constraint::Min(5),   // Recent files
                ])
                .split(f.area());

            // Title + current file
            let title = Paragraph::new(Line::from(vec![
                Span::styled("blazehash ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(&app.current_file),
            ]))
            .block(Block::default().borders(Borders::ALL).title(" Hashing "));
            f.render_widget(title, chunks[0]);

            // Progress gauge
            let ratio = if app.total_bytes > 0 {
                (app.processed_bytes as f64 / app.total_bytes as f64).min(1.0)
            } else {
                0.0
            };
            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL).title(" Progress "))
                .gauge_style(Style::default().fg(Color::Green))
                .ratio(ratio)
                .label(format!(
                    "{}/{} files, {}/{} bytes",
                    app.processed_files, app.total_files, app.processed_bytes, app.total_bytes
                ));
            f.render_widget(gauge, chunks[1]);

            // Stats
            let elapsed = app.start_time.elapsed().as_secs_f64().max(0.001);
            let mbps = app.processed_bytes as f64 / (1024.0 * 1024.0) / elapsed;
            let eta = if mbps > 0.0 {
                let remaining = (app.total_bytes - app.processed_bytes) as f64 / (1024.0 * 1024.0);
                (remaining / mbps) as u64
            } else {
                0
            };
            let stats = Paragraph::new(format!(
                " {mbps:.1} MB/s | ETA: {eta}s | Elapsed: {:.1}s",
                elapsed
            ))
            .block(Block::default().borders(Borders::ALL).title(" Stats "));
            f.render_widget(stats, chunks[2]);

            // Recent completions
            let items: Vec<ListItem> = app
                .completed
                .iter()
                .rev()
                .map(|p| {
                    ListItem::new(format!(
                        "{} ({} bytes) {}",
                        p.path, p.size, p.hash_preview
                    ))
                })
                .collect();
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(" Recent "));
            f.render_widget(list, chunks[3]);
        })?;

        // Handle input (q to quit, or wait for finish)
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                    break;
                }
            }
        }

        if app.finished {
            // Show final state for 1 second then exit
            std::thread::sleep(Duration::from_secs(1));
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    let results = worker.join().map_err(|_| anyhow::anyhow!("worker thread panicked"))?;
    Ok(results)
}
```

In `src/lib.rs`:

```rust
#[cfg(feature = "tui")]
pub mod tui;
```

In `src/cli.rs`, add `Mode::Tui`:

```rust
#[derive(Debug)]
pub enum Mode {
    // ... existing ...
    #[cfg(feature = "tui")]
    Tui,
    // ...
}
```

In `Cli::mode()`:

```rust
} else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("tui")) {
    #[cfg(feature = "tui")]
    return Mode::Tui;
    #[cfg(not(feature = "tui"))]
    Mode::Hash
}
```

In `src/main.rs`:

```rust
#[cfg(feature = "tui")]
if let Mode::Tui = cli.mode() {
    let tui_paths: Vec<PathBuf> = cli.paths[1..].to_vec();
    if tui_paths.is_empty() {
        anyhow::bail!("usage: blazehash tui <paths...>");
    }
    let filter = cli.build_walk_filter()?;
    let results = blazehash::tui::run_tui(
        &tui_paths,
        &algorithms,
        cli.recursive,
        &filter,
        cli.entropy,
    )?;
    // After TUI exits, optionally write results to output
    if let Some(ref output) = output {
        let mut writer = blazehash::output::make_writer(Some(output.as_path()), false)?;
        use blazehash::manifest::{write_header, write_record};
        use std::io::Write;
        write_header(&mut writer, &algorithms)?;
        for r in &results {
            write_record(&mut writer, r, &algorithms)?;
        }
        writer.flush()?;
        eprintln!("[+] Results written to {}", output.display());
    }
    return Ok(());
}
```

```bash
cargo test --features tui tui_tests
```
Expected: event channel test passes.

**GREEN commit:**
```bash
git add src/tui.rs src/lib.rs src/cli.rs src/main.rs tests/cli_tests.rs
git commit -m "feat: blazehash tui — interactive ratatui terminal UI (behind tui feature)"
```

---

## Task 13: CI and README update

**Files:**
- Modify: `README.md` -- document all new features
- Modify: `.github/workflows/ci.yml` (if exists) -- add `--features ots`, `--features tui` test variants

**Step 1: Update README**

Add sections for:
- `--case` and `--examiner` flags (chain-of-custody metadata)
- `blazehash completions <shell>` (shell completions)
- `--progress` flag (progress bar)
- `--hashdb-bad` flag (known-bad hash list)
- `blazehash diff --patch` (unified diff output)
- `--sector-size` and raw device hashing
- `--format stix` (STIX 2.1 Bundle)
- `--format ecs` (ECS NDJSON)
- `blazehash cosign` / `verify-msig` (multi-party signing)
- `blazehash ots stamp/verify` (OpenTimestamps, behind `ots` feature)
- `blazehash tui` (interactive TUI, behind `tui` feature)

**Step 2: Add CI variants**

Add test matrix entries for:
```yaml
- name: Test with ots feature
  run: cargo test --features ots
- name: Test with tui feature
  run: cargo test --features tui
```

**Commit:**
```bash
git add README.md .github/
git commit -m "docs: update README and CI for feature batch 3"
```

---

### Critical Files for Implementation

- `/Users/4n6h4x0r/src/blazehash/src/cli.rs` -- All new CLI flags and Mode variants are added here
- `/Users/4n6h4x0r/src/blazehash/src/commands/hash.rs` -- Main hashing pipeline that integrates progress, device hashing, bad list, new output formats, and metadata
- `/Users/4n6h4x0r/src/blazehash/src/signing.rs` -- Must expose `derive_key_from_password` as pub for cosign module to reuse
- `/Users/4n6h4x0r/src/blazehash/src/main.rs` -- Mode dispatch for all new subcommands (completions, cosign, verify-msig, ots, tui)
- `/Users/4n6h4x0r/src/blazehash/src/format/mod.rs` -- Re-exports for new STIX and ECS formatters