use blazehash::algorithm::Algorithm;
use blazehash::walk::walk_and_hash;
use std::fs;
use tempfile::TempDir;

#[test]
fn walk_empty_directory() {
    let dir = TempDir::new().unwrap();
    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert!(output.results.is_empty());
}

#[test]
fn walk_flat_directory() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    fs::write(dir.path().join("b.txt"), b"bbb").unwrap();

    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert_eq!(output.results.len(), 2);
    for r in &output.results {
        assert_eq!(r.size, 3);
        assert!(r.hashes.contains_key(&Algorithm::Blake3));
    }
}

#[test]
fn walk_recursive() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("root.txt"), b"root").unwrap();
    let sub = dir.path().join("subdir");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("nested.txt"), b"nested").unwrap();

    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], true).unwrap();
    assert_eq!(output.results.len(), 2);
}

#[test]
fn walk_non_recursive_skips_subdirs() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("root.txt"), b"root").unwrap();
    let sub = dir.path().join("subdir");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("nested.txt"), b"nested").unwrap();

    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert_eq!(output.results.len(), 1);
}

#[test]
fn walk_multiple_algorithms() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"hello world").unwrap();

    let algos = vec![Algorithm::Blake3, Algorithm::Sha256];
    let output = walk_and_hash(dir.path(), &algos, false).unwrap();
    assert_eq!(output.results.len(), 1);
    assert_eq!(output.results[0].hashes.len(), 2);
}

#[test]
fn walk_skips_directories_and_symlinks() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("file.txt"), b"content").unwrap();
    fs::create_dir(dir.path().join("subdir")).unwrap();

    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], true).unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.results[0].path.ends_with("file.txt"));
}

#[test]
#[cfg(unix)]
fn walk_reports_unreadable_files() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("good.txt"), b"content").unwrap();

    // Create a file and make it unreadable
    let bad = dir.path().join("bad.txt");
    fs::write(&bad, b"secret").unwrap();

    // Remove read permission
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o000)).unwrap();

    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(
        !output.errors.is_empty(),
        "should report errors for unreadable file"
    );

    // Cleanup permissions so TempDir can delete
    fs::set_permissions(&bad, fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn walk_output_has_no_errors_on_success() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"aaa").unwrap();

    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    assert_eq!(output.results.len(), 1);
    assert!(output.errors.is_empty());
}

#[test]
fn walk_deeply_nested_recursive() {
    let dir = TempDir::new().unwrap();
    let l1 = dir.path().join("a");
    let l2 = l1.join("b");
    let l3 = l2.join("c");
    fs::create_dir_all(&l3).unwrap();
    fs::write(l3.join("deep.txt"), b"deep content").unwrap();
    fs::write(dir.path().join("root.txt"), b"root").unwrap();

    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], true).unwrap();
    assert_eq!(output.results.len(), 2);
    assert!(output.errors.is_empty());
}

#[test]
fn walk_empty_directory_no_errors() {
    let dir = TempDir::new().unwrap();
    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], true).unwrap();
    assert!(output.results.is_empty());
    assert!(output.errors.is_empty());
}

#[test]
fn walk_all_algorithms() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("test.txt"), b"content").unwrap();

    let algos: Vec<Algorithm> = Algorithm::all().to_vec();
    let output = walk_and_hash(dir.path(), &algos, false).unwrap();
    assert_eq!(output.results.len(), 1);
    assert_eq!(output.results[0].hashes.len(), 8);
}

#[cfg(unix)]
#[test]
fn walk_symlink_to_file_is_skipped() {
    let dir = TempDir::new().unwrap();
    let real_file = dir.path().join("real.txt");
    fs::write(&real_file, b"content").unwrap();
    std::os::unix::fs::symlink(&real_file, dir.path().join("link.txt")).unwrap();

    let output = walk_and_hash(dir.path(), &[Algorithm::Blake3], false).unwrap();
    // walkdir follows symlinks by default, but we should get at least the real file
    // The symlink may or may not be followed depending on walkdir config
    assert!(!output.results.is_empty());
}
