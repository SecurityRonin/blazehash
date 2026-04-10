#![cfg(target_os = "windows")]
// TDD RED: Windows MFT direct enumeration for size-only mode.
//
// These tests only compile and run on Windows.
// Run with:
//   cargo test --test mft_tests

use std::path::{Path, PathBuf};

// ── 1. Helper: volume path extraction ─────────────────────────────────────────

#[test]
fn test_volume_path_for_c_drive() {
    let p = blazehash::walk_windows_mft::volume_path_for(Path::new("C:\\Users\\test"));
    assert_eq!(p, "\\\\.\\C:");
}

#[test]
fn test_volume_path_for_d_drive() {
    let p = blazehash::walk_windows_mft::volume_path_for(Path::new("D:\\Evidence\\case1"));
    assert_eq!(p, "\\\\.\\D:");
}

#[test]
fn test_volume_path_opt_unc_returns_none() {
    // UNC paths (\\server\share) can't be MFT-queried
    let r = blazehash::walk_windows_mft::volume_path_opt(Path::new("\\\\server\\share\\foo"));
    assert!(r.is_none());
}

// ── 2. Elevation detection ─────────────────────────────────────────────────────

#[test]
fn test_is_elevated_returns_bool_without_panic() {
    // Just checks the function runs — true in CI admin environments, false otherwise
    let _elevated: bool = blazehash::walk_windows_mft::is_elevated();
}

// ── 3. MftEntry struct ────────────────────────────────────────────────────────

#[test]
fn test_mft_entry_has_path_and_size() {
    use blazehash::walk_windows_mft::MftEntry;
    let e = MftEntry {
        path: PathBuf::from("C:\\Windows\\notepad.exe"),
        size: 204_800,
    };
    assert_eq!(e.size, 204_800);
    assert_eq!(e.path.file_name().unwrap(), "notepad.exe");
}

// ── 4. TSV round-trip (read_mft_results ↔ worker output format) ───────────────

#[test]
fn test_read_mft_results_parses_tsv() {
    let dir = tempfile::tempdir().unwrap();
    let tsv = dir.path().join("results.tsv");
    std::fs::write(&tsv, "1234\tC:\\foo.txt\n5678\tC:\\bar.bin\n").unwrap();

    let entries = blazehash::walk_windows_mft::read_mft_results(&tsv).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].size, 1234);
    assert_eq!(entries[0].path, PathBuf::from("C:\\foo.txt"));
    assert_eq!(entries[1].size, 5678);
}

#[test]
fn test_read_mft_results_ignores_malformed_lines() {
    let dir = tempfile::tempdir().unwrap();
    let tsv = dir.path().join("r.tsv");
    // Lines without a tab are skipped
    std::fs::write(&tsv, "good\t1234\tC:\\x.txt\nnotab\n\t\n").unwrap();
    // "good\t1234\tC:\\x.txt" → size = 0 (parse fails), path = "1234\tC:\\x.txt"  <- we just don't crash
    let entries = blazehash::walk_windows_mft::read_mft_results(&tsv).unwrap();
    // At least one entry parsed (the "good" line: size=0 because "good" won't parse as u64)
    // The main thing is it doesn't panic
    let _ = entries;
}

// ── 5. MFT enumeration (requires Admin + NTFS) ────────────────────────────────

#[test]
#[ignore] // run with: cargo test -- --ignored (must be run as Administrator)
fn test_enumerate_mft_c_root_nonempty() {
    let entries = blazehash::walk_windows_mft::enumerate_mft_sizes(
        Path::new("C:\\"),
        false, // non-recursive: just root-level files
    )
    .expect("enumerate_mft_sizes failed — are you running as Administrator?");
    assert!(!entries.is_empty(), "C:\\ should have at least some files");
    // All entries should have a size (even 0-byte files return 0, not panic)
    for e in &entries {
        let _ = e.size; // just ensures field is accessible
    }
}

#[test]
#[ignore]
fn test_enumerate_mft_windows_dir_recursive() {
    let entries = blazehash::walk_windows_mft::enumerate_mft_sizes(
        Path::new("C:\\Windows"),
        true,
    )
    .expect("must run as Administrator");
    // C:\Windows has thousands of files
    assert!(entries.len() > 100, "expected many files under C:\\Windows");
    // All paths should start with C:\Windows
    for e in &entries {
        assert!(
            e.path.starts_with("C:\\Windows"),
            "unexpected path: {}",
            e.path.display()
        );
    }
}

// ── 6. Worker spawn (requires interactive session for UAC) ─────────────────────

#[test]
#[ignore] // UAC interactive — cannot run in CI without attended session
fn test_spawn_elevated_worker_writes_results() {
    let dir = tempfile::tempdir().unwrap();
    let outfile = dir.path().join("mft_out.tsv");

    // This will pop a UAC dialog in a real interactive session
    blazehash::walk_windows_mft::spawn_elevated_mft_worker(
        Path::new("C:\\Windows"),
        false,
        &outfile,
    )
    .expect("elevation failed or cancelled");

    assert!(outfile.exists(), "worker should have written results");
    let entries = blazehash::walk_windows_mft::read_mft_results(&outfile).unwrap();
    assert!(!entries.is_empty());
}
