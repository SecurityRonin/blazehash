use blazehash::algorithm::Algorithm;
use blazehash::audit::audit;
use blazehash::hash::hash_file;
use blazehash::manifest::{write_header, write_record};
use std::fs;
use std::io::Write;
use tempfile::TempDir;

fn make_known_file(dir: &TempDir) -> String {
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    let result = hash_file(&file, &[Algorithm::Blake3], false, false).unwrap();
    let hash = result.hashes[&Algorithm::Blake3].clone();

    format!(
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n{},{},{}\n",
        result.size,
        hash,
        file.display()
    )
}

#[test]
fn audit_all_matched() {
    let dir = TempDir::new().unwrap();
    let known = make_known_file(&dir);

    let result = audit(&[dir.path().join("test.txt")], &known).unwrap();

    assert_eq!(result.matched, 1);
    assert_eq!(result.new_files, 0);
    assert_eq!(result.changed, 0);
}

#[test]
fn audit_detects_changed_file() {
    let dir = TempDir::new().unwrap();
    let known = make_known_file(&dir);

    fs::write(dir.path().join("test.txt"), b"modified content").unwrap();

    let result = audit(&[dir.path().join("test.txt")], &known).unwrap();

    assert_eq!(result.matched, 0);
    assert_eq!(result.changed, 1);
}

#[test]
fn audit_detects_new_file() {
    let dir = TempDir::new().unwrap();
    let known = make_known_file(&dir);

    fs::write(dir.path().join("new.txt"), b"new file").unwrap();

    let result = audit(
        &[dir.path().join("test.txt"), dir.path().join("new.txt")],
        &known,
    )
    .unwrap();

    assert_eq!(result.matched, 1);
    assert_eq!(result.new_files, 1);
}

#[test]
fn audit_detects_missing_file() {
    let dir = TempDir::new().unwrap();
    let known = make_known_file(&dir);

    // Delete the file after generating known hashes
    fs::remove_file(dir.path().join("test.txt")).unwrap();

    // Audit with empty paths list — the known file is missing
    let result = audit(&[], &known).unwrap();

    assert_eq!(result.missing, 1);
}

#[test]
fn audit_skips_malformed_manifest_lines() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();
    let hash_result = hash_file(&file, &[Algorithm::Blake3], false, false).unwrap();
    let hash = hash_result.hashes[&Algorithm::Blake3].clone();

    // Manifest with a malformed line (bad size field)
    let known = format!(
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\nBADSIZE,badhash,/bad/path\n{},{},{}\n",
        hash_result.size,
        hash,
        file.display()
    );

    let result = audit(&[file], &known).unwrap();
    assert_eq!(
        result.matched, 1,
        "should match the valid entry and skip the malformed one"
    );
}

#[test]
fn audit_moved_checks_all_algorithms() {
    let dir = TempDir::new().unwrap();

    // Create known file with two algorithms
    let file = dir.path().join("original.txt");
    fs::write(&file, b"hello world").unwrap();
    let hash_result = hash_file(&file, &[Algorithm::Blake3, Algorithm::Sha256], false, false).unwrap();
    let blake3_hash = hash_result.hashes[&Algorithm::Blake3].clone();
    let sha256_hash = hash_result.hashes[&Algorithm::Sha256].clone();

    let known = format!(
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,sha256,filename\n{},{},{},{}\n",
        hash_result.size,
        blake3_hash,
        sha256_hash,
        file.display()
    );

    // Rename the file (same content, different path = moved)
    let moved_file = dir.path().join("moved.txt");
    fs::rename(&file, &moved_file).unwrap();

    let result = audit(&[moved_file], &known).unwrap();

    assert_eq!(result.moved, 1);
}

#[test]
fn audit_all_new_files() {
    let dir = TempDir::new().unwrap();
    // Create a known manifest for a file that doesn't exist among scanned paths
    let dummy = dir.path().join("dummy.txt");
    fs::write(&dummy, b"dummy").unwrap();
    let hash_result = hash_file(&dummy, &[Algorithm::Blake3], false, false).unwrap();
    let hash = hash_result.hashes[&Algorithm::Blake3].clone();
    let known = format!(
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n{},{},{}\n",
        hash_result.size, hash, "/nonexistent/original.txt"
    );

    // Scan a completely different file
    let new_file = dir.path().join("new.txt");
    fs::write(&new_file, b"brand new content").unwrap();

    let result = audit(&[new_file], &known).unwrap();
    assert_eq!(result.new_files, 1);
    assert_eq!(result.matched, 0);
    assert_eq!(result.missing, 1); // original.txt is missing
}

#[test]
fn audit_empty_paths_list() {
    let dir = TempDir::new().unwrap();
    let known = make_known_file(&dir);

    let result = audit(&[], &known).unwrap();
    assert_eq!(result.matched, 0);
    assert_eq!(result.missing, 1);
}

#[test]
fn audit_changed_size_same_content_impossible_but_handled() {
    // This tests the branch where path matches but hash differs
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();
    let hash_result = hash_file(&file, &[Algorithm::Blake3], false, false).unwrap();
    let hash = hash_result.hashes[&Algorithm::Blake3].clone();

    // Manifest with wrong size but correct hash (artificial scenario)
    let known = format!(
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n999,{},{}\n",
        hash,
        file.display()
    );

    let result = audit(&[file], &known).unwrap();
    // Size mismatch means "changed"
    assert_eq!(result.changed, 1);
}

#[test]
fn audit_details_contains_correct_statuses() {
    use blazehash::audit::AuditStatus;

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();
    let known = make_known_file(&dir);

    let result = audit(&[file.clone()], &known).unwrap();
    assert_eq!(result.details.len(), 1);
    match &result.details[0] {
        AuditStatus::Matched(p) => assert_eq!(p, &file),
        other => panic!("expected Matched, got {other:?}"),
    }
}

#[test]
fn audit_moved_detection_with_single_algorithm() {
    let dir = TempDir::new().unwrap();
    let original = dir.path().join("original.txt");
    fs::write(&original, b"content to move").unwrap();
    let hash_result = hash_file(&original, &[Algorithm::Blake3], false, false).unwrap();
    let hash = hash_result.hashes[&Algorithm::Blake3].clone();

    let known = format!(
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n{},{},{}\n",
        hash_result.size,
        hash,
        original.display()
    );

    // "Move" the file
    let moved = dir.path().join("moved.txt");
    fs::rename(&original, &moved).unwrap();

    let result = audit(&[moved], &known).unwrap();
    assert_eq!(result.moved, 1);
}

#[test]
fn audit_details_new_file_variant() {
    use blazehash::audit::AuditStatus;

    let dir = TempDir::new().unwrap();
    let known = "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n5,deadbeef,/old.txt\n";

    let new_file = dir.path().join("brand_new.txt");
    fs::write(&new_file, b"new").unwrap();

    let result = audit(&[new_file.clone()], known).unwrap();
    assert!(result
        .details
        .iter()
        .any(|d| matches!(d, AuditStatus::New(_))));
}

#[test]
fn audit_details_missing_variant() {
    use blazehash::audit::AuditStatus;

    let dir = TempDir::new().unwrap();
    let known = make_known_file(&dir);
    fs::remove_file(dir.path().join("test.txt")).unwrap();

    let result = audit(&[], &known).unwrap();
    assert!(result
        .details
        .iter()
        .any(|d| matches!(d, AuditStatus::Missing(_))));
}

// ---- Fuzzy audit tests (Task 8) ----

fn make_manifest_content(algorithms: &[Algorithm], entries: &[blazehash::hash::FileHashResult]) -> String {
    let mut buf = Vec::new();
    write_header(&mut buf, algorithms).unwrap();
    for entry in entries {
        write_record(&mut buf, entry, algorithms).unwrap();
    }
    String::from_utf8(buf).unwrap()
}

#[test]
fn test_fuzzy_audit_result_has_fuzzy_matched_field() {
    // AuditResult must have fuzzy_matched field
    let result = blazehash::audit::AuditResult::default();
    assert_eq!(result.fuzzy_matched, 0);
}

#[test]
fn test_audit_function_accepts_fuzzy_params() {
    // audit() must accept fuzzy_threshold and fuzzy_top params
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"test").unwrap();

    let result = hash_file(&file, &[Algorithm::Blake3], false, false).unwrap();
    let manifest = make_manifest_content(&[Algorithm::Blake3], &[result]);

    // Verify new signature compiles and works
    let audit_result = audit(&[file], &manifest, 75, 10).unwrap();
    assert_eq!(audit_result.matched, 1);
}

#[test]
fn test_fuzzy_audit_exact_match_still_works() {
    // Exact hash match still works when fuzzy algorithms are present
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("fox.txt");
    let data = b"The quick brown fox jumps over the lazy dog. ".repeat(20);
    fs::write(&file, &data).unwrap();

    let result = hash_file(
        &file, &[Algorithm::Blake3, Algorithm::Ssdeep], false, false
    ).unwrap();

    let manifest = make_manifest_content(&[Algorithm::Blake3, Algorithm::Ssdeep], &[result]);

    let audit_result = audit(&[file], &manifest, 50, 5).unwrap();
    assert_eq!(audit_result.matched, 1, "exact match must work with fuzzy algos present");
    assert_eq!(audit_result.fuzzy_matched, 0);
}

#[test]
fn test_fuzzy_audit_unrelated_file_is_new() {
    let dir = TempDir::new().unwrap();
    let orig = dir.path().join("orig.txt");
    let data_a: Vec<u8> = (0u8..=127).cycle().take(400).collect();
    fs::write(&orig, &data_a).unwrap();

    let orig_result = hash_file(&orig, &[Algorithm::Ssdeep], false, false).unwrap();
    let manifest = make_manifest_content(&[Algorithm::Ssdeep], &[orig_result]);

    let different = dir.path().join("different.txt");
    let data_b: Vec<u8> = (128u8..=255).cycle().take(400).collect();
    fs::write(&different, &data_b).unwrap();

    let audit_result = audit(
        &[different],
        &manifest,
        50,
        5,
    ).unwrap();

    // Unrelated data should not fuzzy-match above 50%
    let is_new_or_low_fuzzy = audit_result.new_files == 1 || audit_result.fuzzy_matched == 0;
    assert!(is_new_or_low_fuzzy, "unrelated file should be New (not matched), got: matched={} fuzzy_matched={}", audit_result.matched, audit_result.fuzzy_matched);
    assert_eq!(audit_result.matched, 0, "must not be a full match");
}
