use blazehash::resume::ResumeState;
use std::path::PathBuf;

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
