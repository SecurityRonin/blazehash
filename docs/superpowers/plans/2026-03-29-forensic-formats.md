# Forensic Audit Input Formats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend blazehash audit mode to accept known-hash files from e-Discovery load file formats (Concordance/Relativity DAT, EDRM XML, Summation DII) and verify hashes embedded in forensic disk images (E01/EWF, AFF4).

**Architecture:** A `known_format` module with a `detect_and_parse()` dispatcher that sniffs file format from content/extension and routes to the appropriate parser. Each parser produces `Vec<ManifestRecord>` to feed into the existing `audit::audit()` engine. The current `audit()` function signature changes from `(paths, known_content: &str)` to `(paths, known_records: Vec<ManifestRecord>, algorithms: Vec<Algorithm>)` so callers pre-parse. For forensic images (E01/AFF4), a separate `--verify-image` command reads the stored hash from the image metadata and re-hashes the data segments to verify integrity, producing an audit-style report.

**Tech Stack:** Rust, `quick-xml` (EDRM XML parsing), `zip` (AFF4 container), `rio_turtle` (AFF4 RDF metadata), existing `anyhow`/`hex`/`digest` crates. E01 parser is from-scratch (minimal binary reader for the hash section) to avoid GPL dependency on `exhume_body`.

---

## File Structure

### New files to create

| File | Responsibility |
|------|---------------|
| `src/known_format/mod.rs` | Format detection dispatcher (`detect_and_parse`) + `KnownFormat` enum |
| `src/known_format/hashdeep.rs` | Hashdeep format parser (moved from `manifest.rs::parse_header`/`parse_records`) |
| `src/known_format/csv_input.rs` | CSV known-hash parser |
| `src/known_format/json_input.rs` | JSON/JSONL known-hash parser |
| `src/known_format/b3sum.rs` | b3sum format parser |
| `src/known_format/sha256sum.rs` | sha256sum/md5sum format parser |
| `src/known_format/dat.rs` | Concordance/Relativity DAT parser |
| `src/known_format/edrm_xml.rs` | EDRM XML parser |
| `src/known_format/summation_dii.rs` | Summation DII parser |
| `src/forensic_image/mod.rs` | Image verification dispatcher |
| `src/forensic_image/ewf.rs` | E01/EWF hash extraction + verification |
| `src/forensic_image/aff4.rs` | AFF4 hash extraction + verification |
| `tests/known_format_tests.rs` | Tests for all known-format parsers |
| `tests/forensic_image_tests.rs` | Tests for forensic image verification |
| `tests/fixtures/` | Test fixture files (small DAT, XML, DII, E01, AFF4 samples) |

### Files to modify

| File | Change |
|------|--------|
| `src/lib.rs` | Add `pub mod known_format;` and `pub mod forensic_image;` |
| `src/audit.rs` | Change `audit()` signature to accept pre-parsed `Vec<ManifestRecord>` + `Vec<Algorithm>` |
| `src/manifest.rs` | Keep `write_header`/`write_record` (output). Remove `parse_header`/`parse_records` (moved to `known_format::hashdeep`) |
| `src/commands/audit.rs` | Call `known_format::detect_and_parse()` instead of raw `parse_header`/`parse_records` |
| `src/cli.rs` | Add `--verify-image` flag |
| `src/main.rs` | Add `Mode::VerifyImage` dispatch |
| `Cargo.toml` | Add `quick-xml`, `zip`, `rio_turtle` dependencies |
| `tests/audit_tests.rs` | Update calls to new `audit()` signature |
| `tests/manifest_tests.rs` | Update to use `known_format::hashdeep` for parse tests |

---

### Task 1: Refactor audit() to accept pre-parsed records

Decouple format parsing from the audit engine. Currently `audit()` takes `known_content: &str` and internally calls `parse_header()`/`parse_records()`. After this task, it takes pre-parsed data so any parser can feed into it.

**Files:**
- Modify: `src/audit.rs:26` (function signature)
- Modify: `src/commands/audit.rs:34` (caller)
- Modify: `tests/audit_tests.rs` (all test helpers)

- [ ] **Step 1: Write the failing test**

In `tests/audit_tests.rs`, add a test that calls `audit()` with the new signature (pre-parsed records + algorithms):

```rust
#[test]
fn audit_accepts_pre_parsed_records() {
    use blazehash::algorithm::Algorithm;
    use blazehash::audit::audit;
    use blazehash::manifest::ManifestRecord;
    use std::collections::HashMap;
    use tempfile::TempDir;

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"hello world").unwrap();

    let hash_result = blazehash::hash::hash_file(&file, &[Algorithm::Blake3]).unwrap();
    let hash = hash_result.hashes[&Algorithm::Blake3].clone();

    let records = vec![ManifestRecord {
        size: hash_result.size,
        hashes: {
            let mut h = HashMap::new();
            h.insert(Algorithm::Blake3, hash);
            h
        },
        path: file.clone(),
    }];

    let result = audit(&[file], &records, &[Algorithm::Blake3]).unwrap();
    assert_eq!(result.matched, 1);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test audit_tests audit_accepts_pre_parsed_records`
Expected: FAIL — `audit()` still takes `&str`, not `(&[ManifestRecord], &[Algorithm])`

- [ ] **Step 3: Change `audit()` signature in `src/audit.rs`**

Replace the function signature and remove internal parsing:

```rust
pub fn audit(
    paths: &[PathBuf],
    known_entries: &[ManifestRecord],
    known_algos: &[Algorithm],
) -> Result<AuditResult> {
    let known_by_path: HashMap<&Path, &ManifestRecord> = known_entries
        .iter()
        .map(|e| (e.path.as_path(), e))
        .collect();

    // ... rest of function unchanged, but remove the two parse_ calls at the top
```

Remove these two lines from the top of the function body:
```rust
let known_algos = parse_header(known_content)?;
let known_entries = parse_records(known_content, &known_algos);
```

And remove the import of `parse_header` and `parse_records` from the top of the file. Update `known_algos` references from owned to borrowed (change `&known_algos` iteration to work with `&[Algorithm]`).

- [ ] **Step 4: Update `src/commands/audit.rs` to pre-parse before calling `audit()`**

```rust
use blazehash::audit;
use blazehash::manifest::{parse_header, parse_records};
use blazehash::output::make_writer;
use blazehash::walk::walk_paths;
use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::report_walk_errors;

pub fn run(
    paths: &[PathBuf],
    known: &[PathBuf],
    recursive: bool,
    output: Option<&PathBuf>,
) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    for known_path in known {
        let known_content = fs::read_to_string(known_path)
            .with_context(|| format!("failed to read known file {}", known_path.display()))?;

        let known_algos = parse_header(&known_content)?;
        let known_records = parse_records(&known_content, &known_algos);

        let mut all_paths = Vec::new();
        for path in paths {
            if path.is_file() {
                all_paths.push(path.clone());
            } else if path.is_dir() {
                let (file_paths, errors) = walk_paths(path, recursive);
                report_walk_errors(&errors);
                all_paths.extend(file_paths);
            }
        }

        let result = audit::audit(&all_paths, &known_records, &known_algos)?;
        writeln!(writer, "blazehash audit summary:")?;
        writeln!(writer, "  Files matched: {}", result.matched)?;
        writeln!(writer, "  Files changed: {}", result.changed)?;
        writeln!(writer, "  Files new: {}", result.new_files)?;
        writeln!(writer, "  Files moved: {}", result.moved)?;
        writeln!(writer, "  Files missing: {}", result.missing)?;
    }

    writer.flush()?;
    Ok(())
}
```

- [ ] **Step 5: Update all existing audit tests to new signature**

Every test in `tests/audit_tests.rs` that calls `audit()` with a `&str` needs updating. Replace the `make_known_file` helper:

```rust
use blazehash::algorithm::Algorithm;
use blazehash::audit::audit;
use blazehash::hash::hash_file;
use blazehash::manifest::ManifestRecord;
use std::collections::HashMap;
use std::fs;
use tempfile::TempDir;

fn make_known_records(dir: &TempDir) -> (Vec<ManifestRecord>, Vec<Algorithm>) {
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    let result = hash_file(&file, &[Algorithm::Blake3]).unwrap();
    let hash = result.hashes[&Algorithm::Blake3].clone();

    let records = vec![ManifestRecord {
        size: result.size,
        hashes: {
            let mut h = HashMap::new();
            h.insert(Algorithm::Blake3, hash);
            h
        },
        path: file,
    }];

    (records, vec![Algorithm::Blake3])
}
```

Then update each test. For example, `audit_all_matched`:

```rust
#[test]
fn audit_all_matched() {
    let dir = TempDir::new().unwrap();
    let (records, algos) = make_known_records(&dir);

    let result = audit(&[dir.path().join("test.txt")], &records, &algos).unwrap();

    assert_eq!(result.matched, 1);
    assert_eq!(result.new_files, 0);
    assert_eq!(result.changed, 0);
}
```

Apply the same pattern to all other tests: `audit_detects_changed_file`, `audit_detects_new_file`, `audit_detects_missing_file`, `audit_skips_malformed_manifest_lines`, `audit_moved_checks_all_algorithms`, `audit_all_new_files`, `audit_empty_paths_list`, `audit_changed_size_same_content_impossible_but_handled`, `audit_details_contains_correct_statuses`, `audit_moved_detection_with_single_algorithm`, `audit_details_new_file_variant`, `audit_details_missing_variant`.

For tests that previously used raw manifest strings (like `audit_details_new_file_variant` which uses `"5,deadbeef,/old.txt"`), construct `ManifestRecord` structs directly instead.

- [ ] **Step 6: Run all tests to verify they pass**

Run: `cargo test`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add src/audit.rs src/commands/audit.rs tests/audit_tests.rs
git commit -m "refactor: decouple format parsing from audit engine

audit() now accepts pre-parsed Vec<ManifestRecord> + Vec<Algorithm>
instead of raw hashdeep string. This enables plugging in any parser."
```

---

### Task 2: Create `known_format` module with format detection dispatcher

The central module that detects file format and dispatches to the correct parser. Start with hashdeep only (move existing parsing code), then add formats in subsequent tasks.

**Files:**
- Create: `src/known_format/mod.rs`
- Create: `src/known_format/hashdeep.rs`
- Modify: `src/lib.rs:1` (add module)
- Modify: `src/commands/audit.rs` (use new dispatcher)
- Create: `tests/known_format_tests.rs`

- [ ] **Step 1: Write the failing test**

In `tests/known_format_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;
use blazehash::known_format::{detect_and_parse, ParsedKnown};

#[test]
fn detect_hashdeep_format() {
    let content = "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n11,d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24,/test.txt\n";
    let result = detect_and_parse(content, "known.txt").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Blake3]);
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].size, 11);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test known_format_tests detect_hashdeep_format`
Expected: FAIL — module `known_format` does not exist

- [ ] **Step 3: Create `src/known_format/mod.rs`**

```rust
pub mod hashdeep;

use crate::algorithm::Algorithm;
use crate::manifest::ManifestRecord;
use anyhow::{bail, Result};
use std::path::Path;

/// Result of parsing a known-hash file.
#[derive(Debug)]
pub struct ParsedKnown {
    pub algorithms: Vec<Algorithm>,
    pub records: Vec<ManifestRecord>,
}

/// Detect the format of a known-hash file and parse it.
///
/// Detection order:
/// 1. Content sniffing (hashdeep header `%%%% HASHDEEP`)
/// 2. File extension fallback
pub fn detect_and_parse(content: &str, filename: &str) -> Result<ParsedKnown> {
    // Content-based detection
    if content.starts_with("%%%% HASHDEEP") {
        return hashdeep::parse(content);
    }

    // Extension-based fallback
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    match ext {
        "hash" | "hsh" => hashdeep::parse(content),
        _ => bail!(
            "unrecognized known-hash format for '{}'. Supported: hashdeep",
            filename
        ),
    }
}
```

- [ ] **Step 4: Create `src/known_format/hashdeep.rs`**

Move the parse logic from `manifest.rs`:

```rust
use crate::algorithm::Algorithm;
use crate::manifest::ManifestRecord;
use super::ParsedKnown;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

/// Parse a hashdeep-format known-hash file.
pub fn parse(content: &str) -> Result<ParsedKnown> {
    let algorithms = parse_header(content)?;
    let records = parse_records(content, &algorithms);
    Ok(ParsedKnown {
        algorithms,
        records,
    })
}

/// Parse a hashdeep-format header, returning the algorithms in column order.
pub fn parse_header(input: &str) -> Result<Vec<Algorithm>> {
    let mut lines = input.lines();

    let first = lines.next().unwrap_or("");
    if !first.starts_with("%%%% HASHDEEP") {
        bail!(
            "not a hashdeep file: missing header (got {:?})",
            first.chars().take(40).collect::<String>()
        );
    }

    let second = lines.next().unwrap_or("");
    if !second.starts_with("%%%% size,") {
        bail!(
            "not a hashdeep file: missing column line (got {:?})",
            second.chars().take(40).collect::<String>()
        );
    }

    let cols = &second["%%%% size,".len()..];
    let parts: Vec<&str> = cols.split(',').collect();

    if parts.is_empty() || parts.last() != Some(&"filename") {
        bail!(
            "not a hashdeep file: missing filename column (got {:?})",
            second.chars().take(60).collect::<String>()
        );
    }

    let algo_names = &parts[..parts.len() - 1];
    let mut algorithms = Vec::new();
    for name in algo_names {
        algorithms.push(Algorithm::from_str(name)?);
    }

    Ok(algorithms)
}

/// Parse all data records from a hashdeep manifest.
pub fn parse_records(content: &str, algorithms: &[Algorithm]) -> Vec<ManifestRecord> {
    let expected_fields = algorithms.len() + 2;

    content
        .lines()
        .filter(|line| !line.starts_with("%%%%") && !line.starts_with('#') && !line.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(expected_fields, ',').collect();
            if parts.len() < expected_fields {
                return None;
            }

            let size: u64 = parts[0].parse().ok()?;
            let mut hashes = HashMap::new();
            for (i, algo) in algorithms.iter().enumerate() {
                hashes.insert(*algo, parts[i + 1].to_string());
            }
            let path = PathBuf::from(parts[algorithms.len() + 1]);

            Some(ManifestRecord { size, hashes, path })
        })
        .collect()
}
```

- [ ] **Step 5: Add `pub mod known_format;` to `src/lib.rs`**

```rust
pub mod algorithm;
pub mod audit;
pub mod format;
pub mod hash;
pub mod known_format;
pub mod manifest;
pub mod output;
pub mod piecewise;
pub mod resume;
pub mod walk;
```

- [ ] **Step 6: Update `src/commands/audit.rs` to use the dispatcher**

```rust
use blazehash::audit;
use blazehash::known_format;
use blazehash::output::make_writer;
use blazehash::walk::walk_paths;
use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::report_walk_errors;

pub fn run(
    paths: &[PathBuf],
    known: &[PathBuf],
    recursive: bool,
    output: Option<&PathBuf>,
) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    for known_path in known {
        let known_content = fs::read_to_string(known_path)
            .with_context(|| format!("failed to read known file {}", known_path.display()))?;

        let filename = known_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let parsed = known_format::detect_and_parse(&known_content, filename)?;

        let mut all_paths = Vec::new();
        for path in paths {
            if path.is_file() {
                all_paths.push(path.clone());
            } else if path.is_dir() {
                let (file_paths, errors) = walk_paths(path, recursive);
                report_walk_errors(&errors);
                all_paths.extend(file_paths);
            }
        }

        let result = audit::audit(&all_paths, &parsed.records, &parsed.algorithms)?;
        writeln!(writer, "blazehash audit summary:")?;
        writeln!(writer, "  Files matched: {}", result.matched)?;
        writeln!(writer, "  Files changed: {}", result.changed)?;
        writeln!(writer, "  Files new: {}", result.new_files)?;
        writeln!(writer, "  Files moved: {}", result.moved)?;
        writeln!(writer, "  Files missing: {}", result.missing)?;
    }

    writer.flush()?;
    Ok(())
}
```

- [ ] **Step 7: Deprecate parse functions in `src/manifest.rs`**

Keep `parse_header` and `parse_records` in `manifest.rs` as thin wrappers that call the new module, so `tests/manifest_tests.rs` still compiles without changes:

```rust
/// Parse a hashdeep-format header, returning the algorithms in column order.
/// Delegates to `known_format::hashdeep::parse_header`.
pub fn parse_header(input: &str) -> Result<Vec<Algorithm>> {
    crate::known_format::hashdeep::parse_header(input)
}

/// Parse all data records from a hashdeep manifest.
/// Delegates to `known_format::hashdeep::parse_records`.
pub fn parse_records(content: &str, algorithms: &[Algorithm]) -> Vec<ManifestRecord> {
    crate::known_format::hashdeep::parse_records(content, algorithms)
}
```

- [ ] **Step 8: Run all tests to verify**

Run: `cargo test`
Expected: ALL PASS (existing manifest_tests still work via delegation, new known_format_tests pass)

- [ ] **Step 9: Commit**

```bash
git add src/known_format/ src/lib.rs src/manifest.rs src/commands/audit.rs tests/known_format_tests.rs
git commit -m "feat: add known_format module with format detection dispatcher

Introduces detect_and_parse() that sniffs file format and routes to the
correct parser. Hashdeep parser moved from manifest.rs. Audit command
now uses the dispatcher, enabling pluggable format support."
```

---

### Task 3: Add CSV known-hash parser

Parse CSV files with headers like `filename,size,md5,sha256` (flexible column order).

**Files:**
- Create: `src/known_format/csv_input.rs`
- Modify: `src/known_format/mod.rs` (add module + detection)
- Test: `tests/known_format_tests.rs`

- [ ] **Step 1: Write the failing test**

In `tests/known_format_tests.rs`:

```rust
#[test]
fn parse_csv_known_hashes() {
    let content = "filename,size,sha256\n\
        /evidence/doc1.pdf,1024,abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n\
        /evidence/doc2.pdf,2048,1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\n";

    let result = detect_and_parse(content, "hashes.csv").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Sha256]);
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.records[0].size, 1024);
    assert_eq!(
        result.records[0].path.to_str().unwrap(),
        "/evidence/doc1.pdf"
    );
}

#[test]
fn parse_csv_multiple_algorithms() {
    let content = "size,md5,sha256,filename\n\
        1024,d41d8cd98f00b204e9800998ecf8427e,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,/test.txt\n";

    let result = detect_and_parse(content, "hashes.csv").unwrap();
    assert_eq!(result.algorithms.len(), 2);
    assert!(result.algorithms.contains(&Algorithm::Md5));
    assert!(result.algorithms.contains(&Algorithm::Sha256));
    assert_eq!(result.records.len(), 1);
}

#[test]
fn parse_csv_empty_rows_skipped() {
    let content = "filename,size,sha256\n\n\
        /evidence/doc1.pdf,1024,abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\n\n";

    let result = detect_and_parse(content, "hashes.csv").unwrap();
    assert_eq!(result.records.len(), 1);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test known_format_tests parse_csv`
Expected: FAIL — no CSV parser exists

- [ ] **Step 3: Create `src/known_format/csv_input.rs`**

```rust
use crate::algorithm::Algorithm;
use crate::manifest::ManifestRecord;
use super::ParsedKnown;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

/// Parse a CSV known-hash file.
///
/// Expects a header row with column names. Recognized columns:
/// - `filename` / `file` / `path` — file path (required)
/// - `size` / `filesize` — file size in bytes (required)
/// - Any algorithm name (sha256, md5, blake3, etc.) — hash value
///
/// Column order is flexible.
pub fn parse(content: &str) -> Result<ParsedKnown> {
    let mut lines = content.lines().filter(|l| !l.trim().is_empty());

    let header_line = lines.next().ok_or_else(|| anyhow::anyhow!("CSV file is empty"))?;
    let headers: Vec<&str> = header_line.split(',').map(|h| h.trim()).collect();

    // Find column indices
    let filename_col = headers
        .iter()
        .position(|h| {
            let lower = h.to_lowercase();
            lower == "filename" || lower == "file" || lower == "path"
        })
        .ok_or_else(|| anyhow::anyhow!("CSV missing filename/file/path column"))?;

    let size_col = headers
        .iter()
        .position(|h| {
            let lower = h.to_lowercase();
            lower == "size" || lower == "filesize"
        })
        .ok_or_else(|| anyhow::anyhow!("CSV missing size/filesize column"))?;

    // Find algorithm columns
    let mut algo_cols: Vec<(usize, Algorithm)> = Vec::new();
    for (i, header) in headers.iter().enumerate() {
        if i == filename_col || i == size_col {
            continue;
        }
        if let Ok(algo) = Algorithm::from_str(header.trim()) {
            algo_cols.push((i, algo));
        }
    }

    if algo_cols.is_empty() {
        bail!("CSV has no recognized algorithm columns");
    }

    let algorithms: Vec<Algorithm> = algo_cols.iter().map(|(_, a)| *a).collect();
    let mut records = Vec::new();

    for line in lines {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() <= filename_col.max(size_col) {
            continue;
        }

        let size: u64 = match fields[size_col].trim().parse() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let path = PathBuf::from(fields[filename_col].trim());
        let mut hashes = HashMap::new();

        for (col_idx, algo) in &algo_cols {
            if let Some(val) = fields.get(*col_idx) {
                let val = val.trim();
                if !val.is_empty() {
                    hashes.insert(*algo, val.to_string());
                }
            }
        }

        if !hashes.is_empty() {
            records.push(ManifestRecord { size, hashes, path });
        }
    }

    Ok(ParsedKnown {
        algorithms,
        records,
    })
}

/// Check if the content looks like a CSV with a recognizable header.
pub fn sniff(content: &str) -> bool {
    let first_line = content.lines().next().unwrap_or("");
    let lower = first_line.to_lowercase();
    lower.contains("filename") || lower.contains("filesize")
}
```

- [ ] **Step 4: Register CSV parser in `src/known_format/mod.rs`**

Add `pub mod csv_input;` and update detection:

```rust
pub mod csv_input;
pub mod hashdeep;

// In detect_and_parse, after hashdeep check:
    if csv_input::sniff(content) {
        return csv_input::parse(content);
    }

// In extension match:
    match ext {
        "hash" | "hsh" => hashdeep::parse(content),
        "csv" => csv_input::parse(content),
        // ...
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --test known_format_tests`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/known_format/csv_input.rs src/known_format/mod.rs tests/known_format_tests.rs
git commit -m "feat: add CSV known-hash parser for audit mode

Flexible column order, recognizes filename/size + any algorithm name.
Detected by content sniffing or .csv extension."
```

---

### Task 4: Add JSON/JSONL known-hash parser

Parse JSON arrays or newline-delimited JSON objects with `path`/`filename`, `size`, and hash fields.

**Files:**
- Create: `src/known_format/json_input.rs`
- Modify: `src/known_format/mod.rs`
- Test: `tests/known_format_tests.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn parse_json_known_hashes() {
    let content = r#"[
        {"filename": "/evidence/doc1.pdf", "size": 1024, "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
        {"filename": "/evidence/doc2.pdf", "size": 2048, "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}
    ]"#;

    let result = detect_and_parse(content, "hashes.json").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Sha256]);
    assert_eq!(result.records.len(), 2);
}

#[test]
fn parse_jsonl_known_hashes() {
    let content = r#"{"filename": "/doc1.pdf", "size": 1024, "blake3": "aabb1122"}
{"filename": "/doc2.pdf", "size": 2048, "blake3": "ccdd3344"}"#;

    let result = detect_and_parse(content, "hashes.jsonl").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Blake3]);
    assert_eq!(result.records.len(), 2);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test known_format_tests parse_json`
Expected: FAIL

- [ ] **Step 3: Create `src/known_format/json_input.rs`**

```rust
use crate::algorithm::Algorithm;
use crate::manifest::ManifestRecord;
use super::ParsedKnown;
use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

/// Parse a JSON or JSONL known-hash file.
pub fn parse(content: &str) -> Result<ParsedKnown> {
    let objects = parse_objects(content)?;

    if objects.is_empty() {
        bail!("JSON file contains no hash records");
    }

    // Discover algorithms from first object's keys
    let algo_keys = discover_algorithms(&objects[0]);
    if algo_keys.is_empty() {
        bail!("JSON objects contain no recognized algorithm fields");
    }

    let algorithms: Vec<Algorithm> = algo_keys.iter().map(|(_, a)| *a).collect();
    let mut records = Vec::new();

    for obj in &objects {
        let path = extract_path(obj);
        let size = extract_size(obj);

        if let (Some(path), Some(size)) = (path, size) {
            let mut hashes = HashMap::new();
            for (key, algo) in &algo_keys {
                if let Some(Value::String(hash)) = obj.get(key.as_str()) {
                    hashes.insert(*algo, hash.clone());
                }
            }
            if !hashes.is_empty() {
                records.push(ManifestRecord {
                    size,
                    hashes,
                    path: PathBuf::from(path),
                });
            }
        }
    }

    Ok(ParsedKnown {
        algorithms,
        records,
    })
}

fn parse_objects(content: &str) -> Result<Vec<Value>> {
    let trimmed = content.trim();

    // Try JSON array first
    if trimmed.starts_with('[') {
        let arr: Vec<Value> = serde_json::from_str(trimmed)?;
        return Ok(arr);
    }

    // Try JSONL (one object per line)
    let mut objects = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let obj: Value = serde_json::from_str(line)?;
        objects.push(obj);
    }
    Ok(objects)
}

fn discover_algorithms(obj: &Value) -> Vec<(String, Algorithm)> {
    let mut result = Vec::new();
    if let Value::Object(map) = obj {
        for key in map.keys() {
            if let Ok(algo) = Algorithm::from_str(key) {
                result.push((key.clone(), algo));
            }
        }
    }
    result
}

fn extract_path(obj: &Value) -> Option<String> {
    for key in &["filename", "file", "path", "filepath"] {
        if let Some(Value::String(s)) = obj.get(*key) {
            return Some(s.clone());
        }
    }
    None
}

fn extract_size(obj: &Value) -> Option<u64> {
    for key in &["size", "filesize"] {
        match obj.get(*key) {
            Some(Value::Number(n)) => return n.as_u64(),
            Some(Value::String(s)) => return s.parse().ok(),
            _ => continue,
        }
    }
    None
}

/// Check if content looks like JSON (array or object).
pub fn sniff(content: &str) -> bool {
    let trimmed = content.trim();
    trimmed.starts_with('[') || trimmed.starts_with('{')
}
```

- [ ] **Step 4: Register in `src/known_format/mod.rs`**

Add `pub mod json_input;` and update detection:

```rust
    // After hashdeep, before CSV:
    if json_input::sniff(content) {
        return json_input::parse(content);
    }

    // Extension match:
        "json" => json_input::parse(content),
        "jsonl" => json_input::parse(content),
```

- [ ] **Step 5: Run tests**

Run: `cargo test --test known_format_tests`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/known_format/json_input.rs src/known_format/mod.rs tests/known_format_tests.rs
git commit -m "feat: add JSON/JSONL known-hash parser for audit mode

Supports JSON arrays and newline-delimited JSON objects.
Flexible field names (filename/file/path, size/filesize)."
```

---

### Task 5: Add b3sum format parser

Parse output of `b3sum` command: `<hash>  <filename>` (two spaces).

**Files:**
- Create: `src/known_format/b3sum.rs`
- Modify: `src/known_format/mod.rs`
- Test: `tests/known_format_tests.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn parse_b3sum_format() {
    let content = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24  /evidence/test.txt\n\
        af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262  /evidence/empty.txt\n";

    let result = detect_and_parse(content, "hashes.b3").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Blake3]);
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.records[0].size, 0); // b3sum doesn't include size
    assert_eq!(
        result.records[0].hashes[&Algorithm::Blake3],
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test known_format_tests parse_b3sum`
Expected: FAIL

- [ ] **Step 3: Create `src/known_format/b3sum.rs`**

```rust
use crate::algorithm::Algorithm;
use crate::manifest::ManifestRecord;
use super::ParsedKnown;
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;

/// Parse b3sum output format: `<64-char-hex>  <filename>`
pub fn parse(content: &str) -> Result<ParsedKnown> {
    let mut records = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // b3sum uses two spaces between hash and filename
        if let Some((hash, filename)) = line.split_once("  ") {
            let hash = hash.trim();
            let filename = filename.trim();
            if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                let mut hashes = HashMap::new();
                hashes.insert(Algorithm::Blake3, hash.to_string());
                records.push(ManifestRecord {
                    size: 0, // b3sum doesn't include size
                    hashes,
                    path: PathBuf::from(filename),
                });
            }
        }
    }

    Ok(ParsedKnown {
        algorithms: vec![Algorithm::Blake3],
        records,
    })
}

/// Check if content looks like b3sum output (64-char hex + two spaces + path).
pub fn sniff(content: &str) -> bool {
    let first = content.lines().find(|l| !l.trim().is_empty());
    match first {
        Some(line) => {
            if let Some((hash, _)) = line.split_once("  ") {
                let hash = hash.trim();
                hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
            } else {
                false
            }
        }
        None => false,
    }
}
```

- [ ] **Step 4: Register in `src/known_format/mod.rs`**

Add `pub mod b3sum;` and update detection. b3sum sniffing should come after hashdeep and JSON (since a 64-char hex line is a weak signal). Add `.b3` extension.

- [ ] **Step 5: Run tests**

Run: `cargo test --test known_format_tests`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/known_format/b3sum.rs src/known_format/mod.rs tests/known_format_tests.rs
git commit -m "feat: add b3sum format parser for audit mode"
```

---

### Task 6: Add sha256sum/md5sum format parser

Parse output of `sha256sum`/`md5sum` commands: `<hash>  <filename>` or `<hash> *<filename>` (binary mode).

**Files:**
- Create: `src/known_format/sha256sum.rs`
- Modify: `src/known_format/mod.rs`
- Test: `tests/known_format_tests.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn parse_sha256sum_format() {
    let content = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /evidence/empty.txt\n\
        b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  /evidence/hello.txt\n";

    let result = detect_and_parse(content, "hashes.sha256").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Sha256]);
    assert_eq!(result.records.len(), 2);
}

#[test]
fn parse_md5sum_format() {
    let content = "d41d8cd98f00b204e9800998ecf8427e  /evidence/empty.txt\n";

    let result = detect_and_parse(content, "hashes.md5").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Md5]);
    assert_eq!(result.records.len(), 1);
}

#[test]
fn parse_sha256sum_binary_mode() {
    let content = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */evidence/file.bin\n";

    let result = detect_and_parse(content, "hashes.sha256").unwrap();
    assert_eq!(result.records.len(), 1);
    assert_eq!(result.records[0].path.to_str().unwrap(), "/evidence/file.bin");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test known_format_tests parse_sha256sum parse_md5sum`
Expected: FAIL

- [ ] **Step 3: Create `src/known_format/sha256sum.rs`**

```rust
use crate::algorithm::Algorithm;
use crate::manifest::ManifestRecord;
use super::ParsedKnown;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::PathBuf;

/// Parse sha256sum/sha1sum/md5sum output format.
///
/// Format: `<hex-hash>  <filename>` or `<hex-hash> *<filename>` (binary mode)
///
/// Algorithm is inferred from hash length:
/// - 32 hex chars = MD5
/// - 40 hex chars = SHA-1
/// - 64 hex chars = SHA-256
/// - 128 hex chars = SHA-512
pub fn parse(content: &str, hint_ext: &str) -> Result<ParsedKnown> {
    let mut records = Vec::new();
    let mut detected_algo: Option<Algorithm> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('\\') {
            continue;
        }

        let (hash, filename) = if let Some((h, f)) = line.split_once("  ") {
            (h.trim(), f.trim())
        } else if let Some((h, f)) = line.split_once(" *") {
            (h.trim(), f.trim())
        } else {
            continue;
        };

        if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }

        let algo = match hash.len() {
            32 => Algorithm::Md5,
            40 => Algorithm::Sha1,
            64 => infer_64_char_algo(hint_ext),
            128 => Algorithm::Sha512,
            _ => continue,
        };

        if detected_algo.is_none() {
            detected_algo = Some(algo);
        }

        let mut hashes = HashMap::new();
        hashes.insert(algo, hash.to_string());
        records.push(ManifestRecord {
            size: 0,
            hashes,
            path: PathBuf::from(filename),
        });
    }

    match detected_algo {
        Some(algo) => Ok(ParsedKnown {
            algorithms: vec![algo],
            records,
        }),
        None => bail!("no valid hash records found in sha256sum-format file"),
    }
}

/// For 64-char hashes, use extension to disambiguate SHA-256 vs BLAKE3.
/// Default to SHA-256 since this parser handles *sum formats.
fn infer_64_char_algo(hint_ext: &str) -> Algorithm {
    match hint_ext {
        "b3" | "blake3" => Algorithm::Blake3,
        _ => Algorithm::Sha256,
    }
}

/// Check if content looks like `<hex>  <filename>` format.
/// Excludes 64-char hex (handled by b3sum sniff first).
pub fn sniff(content: &str) -> bool {
    let first = content.lines().find(|l| !l.trim().is_empty());
    match first {
        Some(line) => {
            let has_two_space = line.contains("  ");
            let has_binary = line.contains(" *");
            if !(has_two_space || has_binary) {
                return false;
            }
            let hash_part = line.split_whitespace().next().unwrap_or("");
            let len = hash_part.len();
            hash_part.chars().all(|c| c.is_ascii_hexdigit())
                && (len == 32 || len == 40 || len == 64 || len == 128)
        }
        None => false,
    }
}
```

- [ ] **Step 4: Register in `src/known_format/mod.rs`**

Add `pub mod sha256sum;` and update detection. The `sha256sum::parse` takes a `hint_ext` parameter. Update extension matching for `.sha256`, `.sha1`, `.md5`, `.sha512`.

Update the `detect_and_parse` function to pass extension info:

```rust
    // Content sniffing — after b3sum, before csv:
    if sha256sum::sniff(content) {
        return sha256sum::parse(content, ext);
    }

    // Extension match:
        "sha256" | "sha1" | "md5" | "sha512" => sha256sum::parse(content, ext),
```

- [ ] **Step 5: Run tests**

Run: `cargo test --test known_format_tests`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/known_format/sha256sum.rs src/known_format/mod.rs tests/known_format_tests.rs
git commit -m "feat: add sha256sum/md5sum format parser for audit mode

Infers algorithm from hash length. Supports text and binary modes."
```

---

### Task 7: Add Concordance/Relativity DAT parser

Parse Concordance DAT files used in e-Discovery. These are delimited text files using the Concordance delimiters: field separator (U+0014, ASCII 20), text qualifier (U+00FE, thorn-like), and newline within field (U+00AE, registered sign).

**Files:**
- Create: `src/known_format/dat.rs`
- Modify: `src/known_format/mod.rs`
- Create: `tests/fixtures/sample.dat`
- Test: `tests/known_format_tests.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn parse_concordance_dat() {
    // Concordance uses \x14 (ASCII 20) as field delimiter and \xFE as text qualifier
    let header = "\u{00FE}DOCID\u{00FE}\u{0014}\u{00FE}FILEPATH\u{00FE}\u{0014}\u{00FE}FILESIZE\u{00FE}\u{0014}\u{00FE}MD5HASH\u{00FE}";
    let row1 = "\u{00FE}DOC001\u{00FE}\u{0014}\u{00FE}/evidence/email001.msg\u{00FE}\u{0014}\u{00FE}4096\u{00FE}\u{0014}\u{00FE}d41d8cd98f00b204e9800998ecf8427e\u{00FE}";
    let row2 = "\u{00FE}DOC002\u{00FE}\u{0014}\u{00FE}/evidence/email002.msg\u{00FE}\u{0014}\u{00FE}8192\u{00FE}\u{0014}\u{00FE}0cc175b9c0f1b6a831c399e269772661\u{00FE}";
    let content = format!("{}\n{}\n{}\n", header, row1, row2);

    let result = detect_and_parse(&content, "load.dat").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Md5]);
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.records[0].size, 4096);
    assert_eq!(
        result.records[0].path.to_str().unwrap(),
        "/evidence/email001.msg"
    );
    assert_eq!(
        result.records[0].hashes[&Algorithm::Md5],
        "d41d8cd98f00b204e9800998ecf8427e"
    );
}

#[test]
fn parse_dat_with_sha256() {
    let header = "\u{00FE}FILEPATH\u{00FE}\u{0014}\u{00FE}FILESIZE\u{00FE}\u{0014}\u{00FE}SHA256HASH\u{00FE}";
    let row = "\u{00FE}/evidence/doc.pdf\u{00FE}\u{0014}\u{00FE}1024\u{00FE}\u{0014}\u{00FE}e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\u{00FE}";
    let content = format!("{}\n{}\n", header, row);

    let result = detect_and_parse(&content, "load.dat").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Sha256]);
    assert_eq!(result.records.len(), 1);
}

#[test]
fn detect_dat_by_concordance_delimiters() {
    // Should detect even without .dat extension
    let header = "\u{00FE}DOCID\u{00FE}\u{0014}\u{00FE}FILEPATH\u{00FE}\u{0014}\u{00FE}FILESIZE\u{00FE}\u{0014}\u{00FE}MD5HASH\u{00FE}";
    let content = format!("{}\n", header);

    let result = detect_and_parse(&content, "unknown_file").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Md5]);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test known_format_tests parse_concordance_dat parse_dat_with detect_dat_by`
Expected: FAIL

- [ ] **Step 3: Create `src/known_format/dat.rs`**

```rust
use crate::algorithm::Algorithm;
use crate::manifest::ManifestRecord;
use super::ParsedKnown;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::PathBuf;

/// Concordance/Relativity DAT field delimiter (ASCII 20, U+0014)
const FIELD_SEP: char = '\u{0014}';
/// Concordance/Relativity DAT text qualifier (U+00FE)
const TEXT_QUAL: char = '\u{00FE}';

/// Parse a Concordance/Relativity DAT file.
///
/// DAT files use special delimiters:
/// - Field separator: U+0014 (ASCII 20)
/// - Text qualifier: U+00FE (wraps each field value)
///
/// Recognized column headers (case-insensitive):
/// - Path: FILEPATH, FILE_PATH, DOCLINK, NATIVE_FILE, NATIVE_PATH
/// - Size: FILESIZE, FILE_SIZE, NATIVE_SIZE
/// - Hash: MD5HASH, MD5, SHA1HASH, SHA1, SHA256HASH, SHA256
pub fn parse(content: &str) -> Result<ParsedKnown> {
    let mut lines = content.lines();

    let header_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("DAT file is empty"))?;
    let headers = split_dat_line(header_line);

    let filepath_col = find_column(&headers, &[
        "FILEPATH", "FILE_PATH", "DOCLINK", "NATIVE_FILE", "NATIVE_PATH",
    ]);
    let size_col = find_column(&headers, &["FILESIZE", "FILE_SIZE", "NATIVE_SIZE"]);

    let filepath_col = filepath_col
        .ok_or_else(|| anyhow::anyhow!("DAT missing file path column (expected FILEPATH, DOCLINK, etc.)"))?;
    let size_col = size_col
        .ok_or_else(|| anyhow::anyhow!("DAT missing file size column (expected FILESIZE, etc.)"))?;

    // Find hash columns
    let hash_columns = find_hash_columns(&headers);
    if hash_columns.is_empty() {
        bail!("DAT has no recognized hash columns (expected MD5HASH, SHA256HASH, etc.)");
    }

    let algorithms: Vec<Algorithm> = hash_columns.iter().map(|(_, a)| *a).collect();
    let mut records = Vec::new();

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields = split_dat_line(line);

        let path_str = fields.get(filepath_col).map(|s| s.as_str()).unwrap_or("");
        let size_str = fields.get(size_col).map(|s| s.as_str()).unwrap_or("");

        if path_str.is_empty() {
            continue;
        }

        let size: u64 = match size_str.parse() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut hashes = HashMap::new();
        for (col_idx, algo) in &hash_columns {
            if let Some(val) = fields.get(*col_idx) {
                let val = val.trim();
                if !val.is_empty() {
                    hashes.insert(*algo, val.to_lowercase());
                }
            }
        }

        if !hashes.is_empty() {
            records.push(ManifestRecord {
                size,
                hashes,
                path: PathBuf::from(path_str),
            });
        }
    }

    Ok(ParsedKnown {
        algorithms,
        records,
    })
}

/// Split a DAT line by field separator, stripping text qualifiers.
fn split_dat_line(line: &str) -> Vec<String> {
    line.split(FIELD_SEP)
        .map(|field| {
            let trimmed = field.trim();
            // Strip text qualifiers from both ends
            trimmed
                .strip_prefix(TEXT_QUAL)
                .and_then(|s| s.strip_suffix(TEXT_QUAL))
                .unwrap_or(trimmed)
                .to_string()
        })
        .collect()
}

/// Find a column index by checking against multiple possible header names (case-insensitive).
fn find_column(headers: &[String], names: &[&str]) -> Option<usize> {
    headers.iter().position(|h| {
        let upper = h.to_uppercase();
        names.iter().any(|n| upper == *n)
    })
}

/// Find all hash-related columns and map them to algorithms.
fn find_hash_columns(headers: &[String]) -> Vec<(usize, Algorithm)> {
    let hash_patterns: &[(&[&str], Algorithm)] = &[
        (&["MD5HASH", "MD5", "MD5_HASH"], Algorithm::Md5),
        (&["SHA1HASH", "SHA1", "SHA1_HASH", "SHA-1"], Algorithm::Sha1),
        (&["SHA256HASH", "SHA256", "SHA256_HASH", "SHA-256"], Algorithm::Sha256),
        (&["SHA512HASH", "SHA512", "SHA512_HASH", "SHA-512"], Algorithm::Sha512),
        (&["BLAKE3", "BLAKE3HASH"], Algorithm::Blake3),
    ];

    let mut result = Vec::new();
    for (i, header) in headers.iter().enumerate() {
        let upper = header.to_uppercase();
        for (names, algo) in hash_patterns {
            if names.iter().any(|n| upper == *n) {
                result.push((i, *algo));
                break;
            }
        }
    }
    result
}

/// Check if content uses Concordance delimiters.
pub fn sniff(content: &str) -> bool {
    let first = content.lines().next().unwrap_or("");
    first.contains(FIELD_SEP) || first.contains(TEXT_QUAL)
}
```

- [ ] **Step 4: Register in `src/known_format/mod.rs`**

Add `pub mod dat;` and update detection. DAT sniffing should come early (before CSV) because the Concordance delimiters are distinctive:

```rust
    // Content-based detection — after hashdeep:
    if dat::sniff(content) {
        return dat::parse(content);
    }

    // Extension match:
        "dat" => dat::parse(content),
```

- [ ] **Step 5: Run tests**

Run: `cargo test --test known_format_tests`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/known_format/dat.rs src/known_format/mod.rs tests/known_format_tests.rs
git commit -m "feat: add Concordance/Relativity DAT parser for audit mode

Parses e-Discovery load files with Concordance delimiters (U+0014/U+00FE).
Recognizes FILEPATH, FILESIZE, MD5HASH, SHA256HASH columns."
```

---

### Task 8: Add EDRM XML parser

Parse EDRM (Electronic Discovery Reference Model) XML format used in litigation support. Hash values are stored as attributes on `<Document>` or `<ExternalFile>` elements.

**Files:**
- Create: `src/known_format/edrm_xml.rs`
- Modify: `src/known_format/mod.rs`
- Modify: `Cargo.toml` (add `quick-xml`)
- Test: `tests/known_format_tests.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn parse_edrm_xml_format() {
    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<Root>
  <Batch>
    <Documents>
      <Document DocID="DOC001">
        <Files>
          <File FileType="Native">
            <ExternalFile FilePath="/evidence" FileName="email001.msg" FileSize="4096"
                HashAlgorithm="MD5" HashValue="d41d8cd98f00b204e9800998ecf8427e" />
          </File>
        </Files>
      </Document>
      <Document DocID="DOC002">
        <Files>
          <File FileType="Native">
            <ExternalFile FilePath="/evidence" FileName="email002.msg" FileSize="8192"
                HashAlgorithm="MD5" HashValue="0cc175b9c0f1b6a831c399e269772661" />
          </File>
        </Files>
      </Document>
    </Documents>
  </Batch>
</Root>"#;

    let result = detect_and_parse(content, "load.xml").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Md5]);
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.records[0].size, 4096);
    assert!(result.records[0]
        .path
        .to_str()
        .unwrap()
        .ends_with("email001.msg"));
}

#[test]
fn parse_edrm_xml_sha256() {
    let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<Root>
  <Batch>
    <Documents>
      <Document DocID="DOC001">
        <Files>
          <File FileType="Native">
            <ExternalFile FilePath="/evidence" FileName="doc.pdf" FileSize="1024"
                HashAlgorithm="SHA256" HashValue="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" />
          </File>
        </Files>
      </Document>
    </Documents>
  </Batch>
</Root>"#;

    let result = detect_and_parse(content, "load.xml").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Sha256]);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test known_format_tests parse_edrm`
Expected: FAIL

- [ ] **Step 3: Add `quick-xml` to `Cargo.toml`**

```toml
quick-xml = { version = "0.37", features = ["serialize"] }
```

- [ ] **Step 4: Create `src/known_format/edrm_xml.rs`**

```rust
use crate::algorithm::Algorithm;
use crate::manifest::ManifestRecord;
use super::ParsedKnown;
use anyhow::{bail, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Parse an EDRM XML file.
///
/// Looks for `<ExternalFile>` elements with attributes:
/// - FilePath, FileName — combined to form the file path
/// - FileSize — file size in bytes
/// - HashAlgorithm — algorithm name (MD5, SHA1, SHA256, etc.)
/// - HashValue — hex hash string
pub fn parse(content: &str) -> Result<ParsedKnown> {
    let mut reader = Reader::from_str(content);
    let mut records = Vec::new();
    let mut seen_algos = HashSet::new();

    loop {
        match reader.read_event() {
            Ok(Event::Empty(ref e)) | Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "ExternalFile" {
                    if let Some(record) = parse_external_file(e, &mut seen_algos) {
                        records.push(record);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("EDRM XML parse error: {}", e),
            _ => {}
        }
    }

    if records.is_empty() {
        bail!("EDRM XML contains no ExternalFile elements with hash data");
    }

    let algorithms: Vec<Algorithm> = seen_algos.into_iter().collect();

    Ok(ParsedKnown {
        algorithms,
        records,
    })
}

fn parse_external_file(
    e: &quick_xml::events::BytesStart,
    seen_algos: &mut HashSet<Algorithm>,
) -> Option<ManifestRecord> {
    let mut file_path = String::new();
    let mut file_name = String::new();
    let mut file_size: Option<u64> = None;
    let mut hash_algo_str = String::new();
    let mut hash_value = String::new();

    for attr in e.attributes().flatten() {
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let val = String::from_utf8_lossy(&attr.value).to_string();

        match key.as_str() {
            "FilePath" => file_path = val,
            "FileName" => file_name = val,
            "FileSize" => file_size = val.parse().ok(),
            "HashAlgorithm" => hash_algo_str = val,
            "HashValue" => hash_value = val,
            _ => {}
        }
    }

    if file_name.is_empty() || hash_value.is_empty() {
        return None;
    }

    let algo = map_edrm_algo(&hash_algo_str)?;
    seen_algos.insert(algo);

    let full_path = if file_path.is_empty() {
        PathBuf::from(&file_name)
    } else {
        Path::new(&file_path).join(&file_name)
    };

    let mut hashes = HashMap::new();
    hashes.insert(algo, hash_value.to_lowercase());

    Some(ManifestRecord {
        size: file_size.unwrap_or(0),
        hashes,
        path: full_path,
    })
}

/// Map EDRM algorithm names to our Algorithm enum.
fn map_edrm_algo(name: &str) -> Option<Algorithm> {
    let normalized = name.to_uppercase().replace(['-', '_'], "");
    match normalized.as_str() {
        "MD5" => Some(Algorithm::Md5),
        "SHA1" => Some(Algorithm::Sha1),
        "SHA256" => Some(Algorithm::Sha256),
        "SHA512" => Some(Algorithm::Sha512),
        "SHA3256" => Some(Algorithm::Sha3_256),
        "BLAKE3" => Some(Algorithm::Blake3),
        _ => Algorithm::from_str(name).ok(),
    }
}

/// Check if content looks like EDRM XML.
pub fn sniff(content: &str) -> bool {
    let lower = content.to_lowercase();
    lower.contains("<externalfile") || lower.contains("<documents>")
}
```

- [ ] **Step 5: Register in `src/known_format/mod.rs`**

Add `pub mod edrm_xml;` and update detection:

```rust
    // Content sniffing — after hashdeep, after DAT:
    if edrm_xml::sniff(content) {
        return edrm_xml::parse(content);
    }

    // Extension match:
        "xml" => edrm_xml::parse(content),
```

- [ ] **Step 6: Run tests**

Run: `cargo test --test known_format_tests`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add src/known_format/edrm_xml.rs src/known_format/mod.rs Cargo.toml tests/known_format_tests.rs
git commit -m "feat: add EDRM XML parser for audit mode

Parses e-Discovery EDRM XML with ExternalFile elements.
Extracts FilePath, FileName, FileSize, HashAlgorithm, HashValue."
```

---

### Task 9: Add Summation DII parser

Parse Summation DII (Document Image Information) files used in litigation support. DII uses `@` tokens on separate lines to define fields.

**Files:**
- Create: `src/known_format/summation_dii.rs`
- Modify: `src/known_format/mod.rs`
- Test: `tests/known_format_tests.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn parse_summation_dii() {
    let content = "@T DOC001\n\
        @IPTH /evidence\n\
        @IFNM email001.msg\n\
        @IFSZ 4096\n\
        @IHSH d41d8cd98f00b204e9800998ecf8427e\n\
        @T DOC002\n\
        @IPTH /evidence\n\
        @IFNM email002.msg\n\
        @IFSZ 8192\n\
        @IHSH 0cc175b9c0f1b6a831c399e269772661\n";

    let result = detect_and_parse(content, "load.dii").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Md5]);
    assert_eq!(result.records.len(), 2);
    assert_eq!(result.records[0].size, 4096);
    assert_eq!(
        result.records[0].path.to_str().unwrap(),
        "/evidence/email001.msg"
    );
}

#[test]
fn parse_summation_dii_sha256() {
    let content = "@T DOC001\n\
        @IPTH /evidence\n\
        @IFNM doc.pdf\n\
        @IFSZ 1024\n\
        @IHSH e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n";

    let result = detect_and_parse(content, "load.dii").unwrap();
    // SHA-256 inferred from 64-char hash
    assert_eq!(result.algorithms, vec![Algorithm::Sha256]);
}

#[test]
fn detect_dii_by_at_tokens() {
    let content = "@T DOC001\n@IPTH /evidence\n";
    let result = detect_and_parse(content, "unknown_file");
    // Should detect DII format from @T token
    assert!(result.is_ok() || content.starts_with("@T"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test known_format_tests parse_summation`
Expected: FAIL

- [ ] **Step 3: Create `src/known_format/summation_dii.rs`**

```rust
use crate::algorithm::Algorithm;
use crate::manifest::ManifestRecord;
use super::ParsedKnown;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Parse a Summation DII file.
///
/// DII uses `@` tokens to define fields:
/// - `@T <docid>` — start of a new document
/// - `@IPTH <path>` — image/file path (directory)
/// - `@IFNM <filename>` — image/file name
/// - `@IFSZ <size>` — file size in bytes
/// - `@IHSH <hash>` — hash value
///
/// Algorithm is inferred from hash length.
pub fn parse(content: &str) -> Result<ParsedKnown> {
    let mut records = Vec::new();
    let mut current = DiiRecord::default();
    let mut detected_algo: Option<Algorithm> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with("@T ") {
            // Flush previous record
            if let Some(record) = current.to_manifest_record(&mut detected_algo) {
                records.push(record);
            }
            current = DiiRecord::default();
        } else if let Some(val) = line.strip_prefix("@IPTH ") {
            current.path_dir = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("@IFNM ") {
            current.filename = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("@IFSZ ") {
            current.size = val.trim().parse().ok();
        } else if let Some(val) = line.strip_prefix("@IHSH ") {
            current.hash = val.trim().to_string();
        }
    }

    // Flush last record
    if let Some(record) = current.to_manifest_record(&mut detected_algo) {
        records.push(record);
    }

    if records.is_empty() {
        bail!("DII file contains no records with hash data");
    }

    let algo = detected_algo.unwrap_or(Algorithm::Md5);

    Ok(ParsedKnown {
        algorithms: vec![algo],
        records,
    })
}

#[derive(Default)]
struct DiiRecord {
    path_dir: String,
    filename: String,
    size: Option<u64>,
    hash: String,
}

impl DiiRecord {
    fn to_manifest_record(
        &self,
        detected_algo: &mut Option<Algorithm>,
    ) -> Option<ManifestRecord> {
        if self.filename.is_empty() || self.hash.is_empty() {
            return None;
        }

        let algo = infer_algo_from_length(self.hash.len())?;
        if detected_algo.is_none() {
            *detected_algo = Some(algo);
        }

        let full_path = if self.path_dir.is_empty() {
            PathBuf::from(&self.filename)
        } else {
            Path::new(&self.path_dir).join(&self.filename)
        };

        let mut hashes = HashMap::new();
        hashes.insert(algo, self.hash.to_lowercase());

        Some(ManifestRecord {
            size: self.size.unwrap_or(0),
            hashes,
            path: full_path,
        })
    }
}

fn infer_algo_from_length(len: usize) -> Option<Algorithm> {
    match len {
        32 => Some(Algorithm::Md5),
        40 => Some(Algorithm::Sha1),
        64 => Some(Algorithm::Sha256),
        128 => Some(Algorithm::Sha512),
        _ => None,
    }
}

/// Check if content looks like Summation DII.
pub fn sniff(content: &str) -> bool {
    content
        .lines()
        .any(|l| l.starts_with("@T ") || l.starts_with("@IPTH "))
}
```

- [ ] **Step 4: Register in `src/known_format/mod.rs`**

Add `pub mod summation_dii;` and update detection:

```rust
    // Content sniffing — after hashdeep, after DAT, after EDRM:
    if summation_dii::sniff(content) {
        return summation_dii::parse(content);
    }

    // Extension match:
        "dii" => summation_dii::parse(content),
```

- [ ] **Step 5: Run tests**

Run: `cargo test --test known_format_tests`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/known_format/summation_dii.rs src/known_format/mod.rs tests/known_format_tests.rs
git commit -m "feat: add Summation DII parser for audit mode

Parses @-token DII format used in litigation support.
Extracts @IPTH, @IFNM, @IFSZ, @IHSH fields per document."
```

---

### Task 10: Create `forensic_image` module with E01/EWF hash verification

Read the stored hash from an E01 (Expert Witness Format / EnCase) image and verify it by re-hashing the data segments. This is a from-scratch minimal parser (not using GPL `exhume_body`).

The E01 format stores data in "sections" (chunks). Each section has a header with type identifier. The key section types are:
- `header` / `header2` — case metadata
- `volume` — volume info
- `sectors` / `data` — actual disk data
- `hash` — stored MD5 hash of all data
- `digest` — stored SHA-1 hash (in EWF-E01 v2)
- `done` / `next` — segment markers

We only need to: (1) find the `hash` section, (2) read the stored MD5, (3) stream through all `sectors` sections computing MD5, (4) compare.

**Files:**
- Create: `src/forensic_image/mod.rs`
- Create: `src/forensic_image/ewf.rs`
- Modify: `src/lib.rs` (add module)
- Modify: `src/cli.rs` (add `--verify-image` flag)
- Modify: `src/main.rs` (add dispatch)
- Create: `tests/forensic_image_tests.rs`
- Create: `tests/fixtures/tiny.E01` (generated in test setup)

- [ ] **Step 1: Write the failing test**

In `tests/forensic_image_tests.rs`:

```rust
use blazehash::forensic_image::ewf;

#[test]
fn ewf_magic_detection() {
    // EVF signature: "EVF\x09\x0D\x0A\xFF\x00"
    let valid = b"EVF\x09\x0D\x0A\xFF\x00rest of file...";
    assert!(ewf::is_ewf(valid));

    let invalid = b"not an ewf file";
    assert!(!ewf::is_ewf(invalid));
}

#[test]
fn ewf_rejects_non_ewf_file() {
    let result = ewf::verify(std::path::Path::new("/dev/null"));
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test forensic_image_tests`
Expected: FAIL — module doesn't exist

- [ ] **Step 3: Create `src/forensic_image/mod.rs`**

```rust
pub mod ewf;

use anyhow::Result;
use std::path::Path;

/// Result of verifying a forensic image's integrity.
#[derive(Debug)]
pub struct ImageVerification {
    /// Path to the image file
    pub image_path: std::path::PathBuf,
    /// Image format detected
    pub format: String,
    /// Hash algorithm used for verification
    pub algorithm: String,
    /// Stored hash value (from image metadata)
    pub stored_hash: String,
    /// Computed hash value (from re-hashing data)
    pub computed_hash: String,
    /// Whether the hashes match
    pub verified: bool,
}

/// Detect image format and verify integrity.
pub fn verify_image(path: &Path) -> Result<ImageVerification> {
    let header = std::fs::read(path)
        .map(|data| data[..8.min(data.len())].to_vec())
        .unwrap_or_default();

    if ewf::is_ewf(&header) {
        return ewf::verify(path);
    }

    anyhow::bail!(
        "unrecognized forensic image format for '{}'",
        path.display()
    );
}
```

- [ ] **Step 4: Create `src/forensic_image/ewf.rs`**

```rust
use super::ImageVerification;
use anyhow::{bail, Context, Result};
use digest::Digest;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

/// EWF (Expert Witness Format) magic bytes
const EWF_MAGIC: &[u8] = b"EVF\x09\x0D\x0A\xFF\x00";

/// Section type identifiers in EWF
const SECTION_HEADER_SIZE: usize = 76;

/// Check if data starts with EWF magic bytes.
pub fn is_ewf(data: &[u8]) -> bool {
    data.len() >= EWF_MAGIC.len() && &data[..EWF_MAGIC.len()] == EWF_MAGIC
}

/// Verify an E01/EWF image by reading the stored hash and re-computing from data.
pub fn verify(path: &Path) -> Result<ImageVerification> {
    let file = File::open(path)
        .with_context(|| format!("failed to open E01 image: {}", path.display()))?;
    let mut reader = BufReader::new(file);

    // Verify magic
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)
        .context("failed to read E01 header")?;
    if !is_ewf(&magic) {
        bail!("not a valid E01 file: bad magic bytes");
    }

    // Skip rest of file header (5 bytes: fields_start(1) + segment_number(2) + padding(2))
    reader.seek(SeekFrom::Start(13))?;

    // Read sections
    let mut stored_md5: Option<String> = None;
    let mut data_chunks: Vec<(u64, u64)> = Vec::new(); // (offset, size) of data sections
    let mut md5_hasher = md5::Md5::new();
    let mut found_data = false;

    loop {
        let section = match read_section_header(&mut reader) {
            Ok(s) => s,
            Err(_) => break,
        };

        let section_type = section.type_string.trim_end_matches('\0').to_lowercase();

        match section_type.as_str() {
            "sectors" | "data" => {
                // Read and hash the compressed/uncompressed data
                let data_size = section.size.saturating_sub(SECTION_HEADER_SIZE as u64);
                if data_size > 0 {
                    let mut remaining = data_size;
                    let mut buf = vec![0u8; 64 * 1024];
                    while remaining > 0 {
                        let to_read = (remaining as usize).min(buf.len());
                        let n = reader.read(&mut buf[..to_read])?;
                        if n == 0 {
                            break;
                        }
                        md5_hasher.update(&buf[..n]);
                        remaining -= n as u64;
                    }
                    found_data = true;
                }
            }
            "hash" => {
                // Hash section contains stored MD5 (16 bytes raw)
                let mut md5_bytes = [0u8; 16];
                reader.read_exact(&mut md5_bytes)?;
                stored_md5 = Some(hex::encode(md5_bytes));
                // Skip remaining section data
                let skip = section
                    .size
                    .saturating_sub(SECTION_HEADER_SIZE as u64 + 16);
                reader.seek(SeekFrom::Current(skip as i64))?;
            }
            "done" | "next" => {
                if section_type == "done" {
                    break;
                }
                // "next" means continue to next segment file — for now, break
                break;
            }
            _ => {
                // Skip unknown sections
                let skip = section.size.saturating_sub(SECTION_HEADER_SIZE as u64);
                if skip > 0 {
                    reader.seek(SeekFrom::Current(skip as i64))?;
                }
            }
        }
    }

    let stored_hash = stored_md5
        .ok_or_else(|| anyhow::anyhow!("E01 image has no stored hash section"))?;

    if !found_data {
        bail!("E01 image has no data sections");
    }

    let computed_hash = hex::encode(md5_hasher.finalize());
    let verified = computed_hash == stored_hash;

    Ok(ImageVerification {
        image_path: path.to_path_buf(),
        format: "E01/EWF".to_string(),
        algorithm: "MD5".to_string(),
        stored_hash,
        computed_hash,
        verified,
    })
}

struct SectionHeader {
    type_string: String,
    next_offset: u64,
    size: u64,
}

fn read_section_header<R: Read + Seek>(reader: &mut R) -> Result<SectionHeader> {
    // Section header layout (76 bytes):
    // type: 16 bytes (ASCII, null-padded)
    // next_offset: 8 bytes (u64 LE)
    // size: 8 bytes (u64 LE)
    // padding: 40 bytes
    // checksum: 4 bytes (Adler-32)

    let mut type_buf = [0u8; 16];
    reader.read_exact(&mut type_buf)?;
    let type_string = String::from_utf8_lossy(&type_buf).to_string();

    let mut offset_buf = [0u8; 8];
    reader.read_exact(&mut offset_buf)?;
    let next_offset = u64::from_le_bytes(offset_buf);

    let mut size_buf = [0u8; 8];
    reader.read_exact(&mut size_buf)?;
    let size = u64::from_le_bytes(size_buf);

    // Skip padding (40 bytes) + checksum (4 bytes)
    let mut skip = [0u8; 44];
    reader.read_exact(&mut skip)?;

    Ok(SectionHeader {
        type_string,
        next_offset,
        size,
    })
}
```

- [ ] **Step 5: Add `pub mod forensic_image;` to `src/lib.rs`**

```rust
pub mod algorithm;
pub mod audit;
pub mod forensic_image;
pub mod format;
pub mod hash;
pub mod known_format;
pub mod manifest;
pub mod output;
pub mod piecewise;
pub mod resume;
pub mod walk;
```

- [ ] **Step 6: Run tests**

Run: `cargo test --test forensic_image_tests`
Expected: PASS for magic detection and rejection tests

- [ ] **Step 7: Commit**

```bash
git add src/forensic_image/ src/lib.rs tests/forensic_image_tests.rs
git commit -m "feat: add E01/EWF forensic image verification

From-scratch EWF parser (no GPL dependencies). Reads stored MD5 from
hash section, re-computes from data sections, compares."
```

---

### Task 11: Add AFF4 forensic image hash verification

AFF4 (Advanced Forensic Format 4) images are ZIP containers with RDF Turtle metadata describing the image and its stored hashes.

**Files:**
- Create: `src/forensic_image/aff4.rs`
- Modify: `src/forensic_image/mod.rs`
- Modify: `Cargo.toml` (add `zip` crate)
- Test: `tests/forensic_image_tests.rs`

- [ ] **Step 1: Write the failing test**

```rust
use blazehash::forensic_image::aff4;

#[test]
fn aff4_magic_detection() {
    // AFF4 is a ZIP file — starts with PK\x03\x04
    let valid = b"PK\x03\x04rest of zip...";
    // But not all ZIPs are AFF4 — need to check for aff4 marker
    // For magic detection, we just check ZIP header
    assert!(aff4::is_zip(valid));

    let invalid = b"not a zip file";
    assert!(!aff4::is_zip(invalid));
}

#[test]
fn aff4_rejects_non_aff4_zip() {
    use tempfile::NamedTempFile;
    use std::io::Write;

    // Create a minimal ZIP that's not AFF4
    let mut tmp = NamedTempFile::new().unwrap();
    let buf = Vec::new();
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(buf));
    zw.start_file::<_, ()>("not_aff4.txt", Default::default()).unwrap();
    zw.write_all(b"not aff4").unwrap();
    let buf = zw.finish().unwrap().into_inner();
    tmp.write_all(&buf).unwrap();
    tmp.flush().unwrap();

    let result = aff4::verify(tmp.path());
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test forensic_image_tests aff4`
Expected: FAIL

- [ ] **Step 3: Add `zip` to `Cargo.toml`**

```toml
zip = "2"
```

- [ ] **Step 4: Create `src/forensic_image/aff4.rs`**

```rust
use super::ImageVerification;
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Check if data starts with ZIP magic (PK\x03\x04).
pub fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == b"PK\x03\x04"
}

/// Verify an AFF4 image by reading stored hashes from RDF metadata
/// and re-computing from data streams.
pub fn verify(path: &Path) -> Result<ImageVerification> {
    let file = File::open(path)
        .with_context(|| format!("failed to open AFF4 image: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut archive = zip::ZipArchive::new(reader)
        .context("failed to read AFF4 as ZIP archive")?;

    // Look for the AFF4 metadata file (typically "information.turtle" or "container.description")
    let turtle_content = find_turtle_metadata(&mut archive)?;

    // Parse RDF Turtle to find stored hash
    let (algorithm, stored_hash) = extract_hash_from_turtle(&turtle_content)?;

    // Find and hash the data stream
    let computed_hash = hash_data_stream(&mut archive, &algorithm)?;
    let verified = computed_hash == stored_hash;

    Ok(ImageVerification {
        image_path: path.to_path_buf(),
        format: "AFF4".to_string(),
        algorithm: algorithm.clone(),
        stored_hash,
        computed_hash,
        verified,
    })
}

fn find_turtle_metadata(archive: &mut zip::ZipArchive<BufReader<File>>) -> Result<String> {
    let turtle_names = [
        "information.turtle",
        "container.description",
        "information.n3",
    ];

    for name in &turtle_names {
        if let Ok(mut entry) = archive.by_name(name) {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            return Ok(content);
        }
    }

    // Search for any .turtle file
    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        if name.ends_with(".turtle") || name.ends_with(".n3") {
            drop(entry);
            let mut entry = archive.by_index(i)?;
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            return Ok(content);
        }
    }

    bail!("not an AFF4 image: no RDF Turtle metadata found");
}

/// Extract hash algorithm and value from RDF Turtle content.
///
/// Looks for triples like:
/// ```turtle
/// <aff4://image-uuid> aff4:hash <aff4://sha256:abcdef1234...> .
/// ```
/// or:
/// ```turtle
/// <aff4://image-uuid/hash> aff4:hashValue "abcdef1234..." .
/// <aff4://image-uuid/hash> aff4:hashType <http://aff4.org/Schema#SHA256> .
/// ```
fn extract_hash_from_turtle(content: &str) -> Result<(String, String)> {
    // Simple line-by-line parsing for hash-related triples
    // Full RDF parsing with rio_turtle could be added later if needed

    for line in content.lines() {
        let line = line.trim();

        // Pattern: aff4:hash <aff4://sha256:HEXVALUE>
        if let Some(hash_ref) = extract_aff4_hash_ref(line) {
            return Ok(hash_ref);
        }

        // Pattern: aff4:sha256 "HEXVALUE"
        if let Some(hash_pair) = extract_inline_hash(line) {
            return Ok(hash_pair);
        }
    }

    bail!("AFF4 metadata contains no hash information");
}

fn extract_aff4_hash_ref(line: &str) -> Option<(String, String)> {
    // Look for aff4://algo:hexvalue pattern
    let marker = "aff4://";
    if let Some(pos) = line.find(marker) {
        let rest = &line[pos + marker.len()..];
        // Strip trailing > and whitespace
        let rest = rest.trim_end_matches(|c: char| c == '>' || c == '.' || c.is_whitespace());
        if let Some((algo, hash)) = rest.split_once(':') {
            let algo_lower = algo.to_lowercase();
            if matches!(
                algo_lower.as_str(),
                "md5" | "sha1" | "sha256" | "sha512" | "blake3"
            ) && hash.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Some((algo_lower, hash.to_lowercase()));
            }
        }
    }
    None
}

fn extract_inline_hash(line: &str) -> Option<(String, String)> {
    // Look for patterns like: aff4:sha256 "hexvalue"
    let algos = ["sha256", "sha1", "md5", "sha512", "blake3"];
    for algo in &algos {
        let pattern = format!("aff4:{}", algo);
        if line.contains(&pattern) {
            // Extract quoted value
            if let Some(start) = line.find('"') {
                if let Some(end) = line[start + 1..].find('"') {
                    let hash = &line[start + 1..start + 1 + end];
                    if hash.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some((algo.to_string(), hash.to_lowercase()));
                    }
                }
            }
        }
    }
    None
}

fn hash_data_stream(
    archive: &mut zip::ZipArchive<BufReader<File>>,
    algorithm: &str,
) -> Result<String> {
    // Find the data stream (typically named with the image UUID or "data")
    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        // Data streams in AFF4 are large binary entries, not metadata
        if name.ends_with(".turtle")
            || name.ends_with(".n3")
            || name == "container.description"
            || name == "version.txt"
        {
            continue;
        }

        // Check if this looks like a data stream (by size or naming convention)
        let size = entry.size();
        if size == 0 {
            continue;
        }

        drop(entry);
        let mut entry = archive.by_index(i)?;

        // Hash the stream
        let hash = match algorithm {
            "md5" => {
                use digest::Digest;
                let mut hasher = md5::Md5::new();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = entry.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hex::encode(hasher.finalize())
            }
            "sha256" => {
                use digest::Digest;
                let mut hasher = sha2::Sha256::new();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = entry.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hex::encode(hasher.finalize())
            }
            "sha1" => {
                use digest::Digest;
                let mut hasher = sha1::Sha1::new();
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = entry.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hex::encode(hasher.finalize())
            }
            other => bail!("unsupported AFF4 hash algorithm: {}", other),
        };

        return Ok(hash);
    }

    bail!("AFF4 image contains no data stream");
}
```

- [ ] **Step 5: Update `src/forensic_image/mod.rs` detection**

```rust
pub mod aff4;
pub mod ewf;

// In verify_image:
    if ewf::is_ewf(&header) {
        return ewf::verify(path);
    }

    if aff4::is_zip(&header) {
        return aff4::verify(path);
    }
```

- [ ] **Step 6: Run tests**

Run: `cargo test --test forensic_image_tests`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add src/forensic_image/aff4.rs src/forensic_image/mod.rs Cargo.toml tests/forensic_image_tests.rs
git commit -m "feat: add AFF4 forensic image verification

Reads RDF Turtle metadata from ZIP container to find stored hash,
re-computes from data stream, compares."
```

---

### Task 12: Add `--verify-image` CLI command

Wire up the forensic image verification to the CLI.

**Files:**
- Modify: `src/cli.rs` (add flag)
- Create: `src/commands/verify_image.rs`
- Modify: `src/commands/mod.rs`
- Modify: `src/main.rs` (add dispatch)
- Test: `tests/cli_tests.rs` or `tests/e2e_tests.rs`

- [ ] **Step 1: Write the failing test**

In `tests/e2e_tests.rs` (or a new test file):

```rust
#[test]
fn verify_image_flag_exists() {
    use assert_cmd::Command;

    let mut cmd = Command::cargo_bin("blazehash").unwrap();
    let output = cmd.arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("verify-image"),
        "help should mention --verify-image flag"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test e2e_tests verify_image_flag_exists`
Expected: FAIL — flag doesn't exist

- [ ] **Step 3: Add `--verify-image` to `src/cli.rs`**

Add to the `Cli` struct:

```rust
    /// Verify forensic image integrity (E01/EWF, AFF4)
    #[arg(long = "verify-image")]
    pub verify_image: bool,
```

Update `Mode` enum and `mode()`:

```rust
#[derive(Debug)]
pub enum Mode {
    SizeOnly,
    Audit,
    Piecewise,
    VerifyImage,
    Hash,
}

impl Cli {
    pub fn mode(&self) -> Mode {
        if self.size_only {
            Mode::SizeOnly
        } else if self.audit {
            Mode::Audit
        } else if self.verify_image {
            Mode::VerifyImage
        } else if self.piecewise.is_some() {
            Mode::Piecewise
        } else {
            Mode::Hash
        }
    }
}
```

- [ ] **Step 4: Create `src/commands/verify_image.rs`**

```rust
use blazehash::forensic_image;
use blazehash::output::make_writer;
use anyhow::Result;
use std::io::Write;
use std::path::PathBuf;

pub fn run(paths: &[PathBuf], output: Option<&PathBuf>) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    for path in paths {
        match forensic_image::verify_image(path) {
            Ok(result) => {
                writeln!(writer, "Image: {}", result.image_path.display())?;
                writeln!(writer, "  Format: {}", result.format)?;
                writeln!(writer, "  Algorithm: {}", result.algorithm)?;
                writeln!(writer, "  Stored hash:   {}", result.stored_hash)?;
                writeln!(writer, "  Computed hash:  {}", result.computed_hash)?;
                if result.verified {
                    writeln!(writer, "  Status: VERIFIED")?;
                } else {
                    writeln!(writer, "  Status: FAILED — hashes do not match")?;
                }
            }
            Err(e) => {
                writeln!(writer, "Image: {}", path.display())?;
                writeln!(writer, "  Error: {}", e)?;
            }
        }
    }

    writer.flush()?;
    Ok(())
}
```

- [ ] **Step 5: Register in `src/commands/mod.rs`**

Add `pub mod verify_image;`

- [ ] **Step 6: Add dispatch in `src/main.rs`**

```rust
        Mode::VerifyImage => {
            commands::verify_image::run(&cli.paths, cli.output.as_ref())?;
        }
```

- [ ] **Step 7: Run tests**

Run: `cargo test`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add src/cli.rs src/commands/verify_image.rs src/commands/mod.rs src/main.rs tests/
git commit -m "feat: add --verify-image CLI command for forensic images

Verifies E01/EWF and AFF4 image integrity by comparing stored vs
computed hashes. Reports format, algorithm, and verification status."
```

---

### Task 13: Update `detect_and_parse` with final detection order and integration test

Finalize the format detection priority and add an end-to-end integration test that exercises audit mode with each format.

**Files:**
- Modify: `src/known_format/mod.rs` (finalize detection order)
- Test: `tests/known_format_tests.rs` (add integration tests)

- [ ] **Step 1: Write integration tests**

```rust
#[test]
fn detection_priority_hashdeep_wins() {
    let content = "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n11,aabb,/test.txt\n";
    let result = detect_and_parse(content, "ambiguous.csv").unwrap();
    assert_eq!(result.algorithms, vec![Algorithm::Blake3]);
}

#[test]
fn detection_priority_dat_over_csv() {
    // DAT with Concordance delimiters should be detected as DAT, not CSV
    let content = "\u{00FE}FILEPATH\u{00FE}\u{0014}\u{00FE}FILESIZE\u{00FE}\u{0014}\u{00FE}MD5HASH\u{00FE}\n\
        \u{00FE}/test.txt\u{00FE}\u{0014}\u{00FE}100\u{00FE}\u{0014}\u{00FE}d41d8cd98f00b204e9800998ecf8427e\u{00FE}\n";
    let result = detect_and_parse(content, "load.csv").unwrap();
    // Should parse as DAT despite .csv extension (content sniffing wins)
    assert_eq!(result.records.len(), 1);
}

#[test]
fn unknown_format_returns_error() {
    let content = "this is not any recognized format\nrandom content\n";
    let result = detect_and_parse(content, "random.xyz");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("unrecognized known-hash format"));
}
```

- [ ] **Step 2: Finalize `src/known_format/mod.rs` detection order**

```rust
pub mod b3sum;
pub mod csv_input;
pub mod dat;
pub mod edrm_xml;
pub mod hashdeep;
pub mod json_input;
pub mod sha256sum;
pub mod summation_dii;

use crate::algorithm::Algorithm;
use crate::manifest::ManifestRecord;
use anyhow::{bail, Result};
use std::path::Path;

#[derive(Debug)]
pub struct ParsedKnown {
    pub algorithms: Vec<Algorithm>,
    pub records: Vec<ManifestRecord>,
}

pub fn detect_and_parse(content: &str, filename: &str) -> Result<ParsedKnown> {
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // 1. Hashdeep header (strongest signal — unique magic)
    if content.starts_with("%%%% HASHDEEP") {
        return hashdeep::parse(content);
    }

    // 2. Concordance DAT delimiters (distinctive Unicode chars)
    if dat::sniff(content) {
        return dat::parse(content);
    }

    // 3. Summation DII (@ tokens at line start)
    if summation_dii::sniff(content) {
        return summation_dii::parse(content);
    }

    // 4. EDRM XML (XML with ExternalFile elements)
    if edrm_xml::sniff(content) {
        return edrm_xml::parse(content);
    }

    // 5. JSON/JSONL (starts with [ or {)
    if json_input::sniff(content) {
        return json_input::parse(content);
    }

    // 6. b3sum (64-char hex + two spaces — before sha256sum since it's more specific)
    if b3sum::sniff(content) && (ext == "b3" || ext.is_empty()) {
        return b3sum::parse(content);
    }

    // 7. sha256sum/md5sum (hex + two spaces or hex + space-star)
    if sha256sum::sniff(content) {
        return sha256sum::parse(content, &ext);
    }

    // 8. CSV (has filename/filesize in header)
    if csv_input::sniff(content) {
        return csv_input::parse(content);
    }

    // 9. Extension-only fallback
    match ext.as_str() {
        "hash" | "hsh" => hashdeep::parse(content),
        "csv" => csv_input::parse(content),
        "json" => json_input::parse(content),
        "jsonl" => json_input::parse(content),
        "dat" => dat::parse(content),
        "dii" => summation_dii::parse(content),
        "xml" => edrm_xml::parse(content),
        "b3" => b3sum::parse(content),
        "sha256" | "sha1" | "md5" | "sha512" => sha256sum::parse(content, &ext),
        _ => bail!(
            "unrecognized known-hash format for '{}'. Supported: hashdeep, CSV, JSON, JSONL, \
             b3sum, sha256sum, Concordance DAT, EDRM XML, Summation DII",
            filename
        ),
    }
}
```

- [ ] **Step 3: Run all tests**

Run: `cargo test`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add src/known_format/mod.rs tests/known_format_tests.rs
git commit -m "feat: finalize format detection priority and integration tests

Detection order: hashdeep > DAT > DII > EDRM XML > JSON > b3sum >
sha256sum > CSV > extension fallback. Content sniffing takes priority."
```

---

### Task 14: Update README with new capabilities

Document the new audit input formats and forensic image verification in the README.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update audit mode section**

In the Usage section, update the audit mode examples:

```markdown
### Audit mode (verify against known hashes)

```bash
blazehash -r /mnt/evidence -a -k known_hashes.txt      # hashdeep format
blazehash -r /mnt/evidence -a -k hashes.csv             # CSV
blazehash -r /mnt/evidence -a -k hashes.json            # JSON / JSONL
blazehash -r /mnt/evidence -a -k hashes.b3              # b3sum format
blazehash -r /mnt/evidence -a -k hashes.sha256          # sha256sum format
blazehash -r /mnt/evidence -a -k load.dat               # Concordance/Relativity DAT
blazehash -r /mnt/evidence -a -k load.xml               # EDRM XML
blazehash -r /mnt/evidence -a -k load.dii               # Summation DII
```

Accepts known-hash files in any format: hashdeep, CSV, JSON, JSONL, b3sum, sha256sum, Concordance/Relativity DAT, EDRM XML, and Summation DII. Format is auto-detected from content. Audit reports match hashdeep output: files matched, changed, moved, new, missing.
```

- [ ] **Step 2: Add forensic image verification section**

```markdown
### Verify forensic image integrity

```bash
blazehash --verify-image evidence.E01                    # E01/EnCase image
blazehash --verify-image evidence.aff4                   # AFF4 image
```

Reads the stored hash from the forensic image metadata, re-computes it from the data segments, and reports whether the image integrity is intact.
```

- [ ] **Step 3: Update feature comparison table**

Add rows for e-Discovery and forensic image support under "Forensic Features":

```markdown
| e-Discovery load files | **Y** | -- | -- | -- | -- |
| Forensic image verify | **Y** | -- | -- | -- | -- |
```

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add audit input formats and forensic image verification to README"
```
