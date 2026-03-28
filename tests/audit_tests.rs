use blazehash::algorithm::Algorithm;
use blazehash::audit::audit;
use blazehash::hash::hash_file;
use std::fs;
use tempfile::TempDir;

fn make_known_file(dir: &TempDir) -> String {
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();

    let result = hash_file(&file, &[Algorithm::Blake3]).unwrap();
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

    let result = audit(
        &[dir.path().join("test.txt")],
        &known,
    )
    .unwrap();

    assert_eq!(result.matched, 1);
    assert_eq!(result.new_files, 0);
    assert_eq!(result.changed, 0);
}

#[test]
fn audit_detects_changed_file() {
    let dir = TempDir::new().unwrap();
    let known = make_known_file(&dir);

    fs::write(dir.path().join("test.txt"), b"modified content").unwrap();

    let result = audit(
        &[dir.path().join("test.txt")],
        &known,
    )
    .unwrap();

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
    let result = audit(
        &[],
        &known,
    )
    .unwrap();

    assert_eq!(result.missing, 1);
}

#[test]
fn audit_skips_malformed_manifest_lines() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("test.txt");
    fs::write(&file, b"hello world").unwrap();
    let hash_result = hash_file(&file, &[Algorithm::Blake3]).unwrap();
    let hash = hash_result.hashes[&Algorithm::Blake3].clone();

    // Manifest with a malformed line (bad size field)
    let known = format!(
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\nBADSIZE,badhash,/bad/path\n{},{},{}\n",
        hash_result.size, hash, file.display()
    );

    let result = audit(&[file], &known).unwrap();
    assert_eq!(result.matched, 1, "should match the valid entry and skip the malformed one");
}

#[test]
fn audit_moved_checks_all_algorithms() {
    let dir = TempDir::new().unwrap();

    // Create known file with two algorithms
    let file = dir.path().join("original.txt");
    fs::write(&file, b"hello world").unwrap();
    let hash_result = hash_file(&file, &[Algorithm::Blake3, Algorithm::Sha256]).unwrap();
    let blake3_hash = hash_result.hashes[&Algorithm::Blake3].clone();
    let sha256_hash = hash_result.hashes[&Algorithm::Sha256].clone();

    let known = format!(
        "%%%% HASHDEEP-1.0\n%%%% size,blake3,sha256,filename\n{},{},{},{}\n",
        hash_result.size, blake3_hash, sha256_hash, file.display()
    );

    // Rename the file (same content, different path = moved)
    let moved_file = dir.path().join("moved.txt");
    fs::rename(&file, &moved_file).unwrap();

    let result = audit(
        &[moved_file],
        &known,
    )
    .unwrap();

    assert_eq!(result.moved, 1);
}
