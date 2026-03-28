use blazehash::resume::ResumeState;
use std::path::{Path, PathBuf};

#[test]
fn resume_state_empty_initially() {
    let state = ResumeState::new();
    assert!(!state.is_done(&PathBuf::from("/some/file.txt")));
    assert_eq!(state.completed_count(), 0);
}

#[test]
fn resume_state_from_partial_manifest() {
    let manifest = "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n11,abcd1234,/evidence/a.txt\n42,ef567890,/evidence/b.txt\n";
    let state = ResumeState::from_manifest(manifest).unwrap();
    assert!(state.is_done(&PathBuf::from("/evidence/a.txt")));
    assert!(state.is_done(&PathBuf::from("/evidence/b.txt")));
    assert!(!state.is_done(&PathBuf::from("/evidence/c.txt")));
    assert_eq!(state.completed_count(), 2);
}

#[test]
fn resume_state_mark_done() {
    let mut state = ResumeState::new();
    state.mark_done(PathBuf::from("/file.txt"));
    assert!(state.is_done(&PathBuf::from("/file.txt")));
    assert_eq!(state.completed_count(), 1);
}

#[test]
fn resume_state_is_done_accepts_path_ref() {
    let mut state = ResumeState::new();
    state.mark_done(PathBuf::from("/file.txt"));
    // Should accept &Path, not just &PathBuf
    assert!(state.is_done(Path::new("/file.txt")));
}

#[test]
fn resume_from_empty_string() {
    let state = ResumeState::from_manifest("").unwrap();
    assert_eq!(state.completed_count(), 0);
}

#[test]
fn resume_from_header_only() {
    let manifest = "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n## Invoked from: blazehash v0.1.0\n##\n";
    let state = ResumeState::from_manifest(manifest).unwrap();
    assert_eq!(state.completed_count(), 0);
}

#[test]
fn resume_skips_lines_without_commas() {
    let manifest = "%%%% HASHDEEP-1.0\nno-comma-here\n11,abcd1234,/file.txt\n";
    let state = ResumeState::from_manifest(manifest).unwrap();
    assert_eq!(state.completed_count(), 1);
    assert!(state.is_done(Path::new("/file.txt")));
}

#[test]
fn resume_mark_done_idempotent() {
    let mut state = ResumeState::new();
    state.mark_done(PathBuf::from("/file.txt"));
    state.mark_done(PathBuf::from("/file.txt"));
    assert_eq!(state.completed_count(), 1);
}

#[test]
fn resume_multiple_algorithms_in_manifest() {
    // With two algorithms, the filename is after the third comma
    let manifest = "11,hash1,hash2,/evidence/file.txt\n";
    let state = ResumeState::from_manifest(manifest).unwrap();
    assert!(state.is_done(Path::new("/evidence/file.txt")));
}

#[test]
fn resume_filename_with_comma() {
    // rfind(',') gets the LAST comma, so a filename with commas will only get the part after the last comma
    // This is a known limitation — test documents the behavior
    let manifest = "11,abcd1234,/path/to/file,with,commas.txt\n";
    let state = ResumeState::from_manifest(manifest).unwrap();
    // Due to rfind, only "commas.txt" is extracted as the path
    assert!(state.is_done(Path::new("commas.txt")));
}
