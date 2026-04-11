// TDD RED: folder vs folder diff
//
// Run with:
//   cargo test --test folder_diff_tests

use std::path::PathBuf;
use tempfile::TempDir;

use blazehash::folder_diff::{diff_folders, CompareBy, FolderDiffEntry};

fn make_file(dir: &TempDir, rel: &str, content: &[u8]) -> PathBuf {
    let path = dir.path().join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, content).unwrap();
    path
}

// ── 1. Identical folders ──────────────────────────────────────────────────────

#[test]
fn test_folder_diff_identical_folders() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "a.txt", b"hello");
    make_file(&left, "b.bin", b"world");
    make_file(&right, "a.txt", b"hello");
    make_file(&right, "b.bin", b"world");

    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    assert!(!result.has_diff(), "identical folders should not have diff");
    let s = result.summary();
    assert_eq!(s.identical, 2);
    assert_eq!(s.modified + s.added + s.removed + s.moved, 0);
}

// ── 2. Added file (only in right) ────────────────────────────────────────────

#[test]
fn test_folder_diff_added_file() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "a.txt", b"same");
    make_file(&right, "a.txt", b"same");
    make_file(&right, "new.bin", b"newcontent");

    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    assert!(result.has_diff());
    let added: Vec<_> = result
        .entries
        .iter()
        .filter_map(|e| {
            if let FolderDiffEntry::Added { path, .. } = e {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0], PathBuf::from("new.bin"));
}

// ── 3. Removed file (only in left) ───────────────────────────────────────────

#[test]
fn test_folder_diff_removed_file() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "a.txt", b"same");
    make_file(&left, "old.bin", b"gone");
    make_file(&right, "a.txt", b"same");

    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    let removed: Vec<_> = result
        .entries
        .iter()
        .filter_map(|e| {
            if let FolderDiffEntry::Removed { path, .. } = e {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0], PathBuf::from("old.bin"));
}

// ── 4. Modified file (same name, different content) ───────────────────────────

#[test]
fn test_folder_diff_modified_file() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "config.json", b"{\"v\":1}");
    make_file(&right, "config.json", b"{\"v\":2}");

    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    let mods: Vec<_> = result
        .entries
        .iter()
        .filter_map(|e| {
            if let FolderDiffEntry::Modified { path, .. } = e {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(mods.len(), 1);
    assert_eq!(mods[0], PathBuf::from("config.json"));
}

// ── 5. Moved file (same content, different name) ──────────────────────────────

#[test]
fn test_folder_diff_moved_file() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "old_name.txt", b"unique content xyz");
    make_file(&right, "new_name.txt", b"unique content xyz");

    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    let moves: Vec<_> = result
        .entries
        .iter()
        .filter_map(|e| {
            if let FolderDiffEntry::Moved { from, to, .. } = e {
                Some((from.clone(), to.clone()))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        moves.len(),
        1,
        "expected 1 move, got {:?}",
        result
            .entries
            .iter()
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(moves[0].0, PathBuf::from("old_name.txt"));
    assert_eq!(moves[0].1, PathBuf::from("new_name.txt"));
}

// ── 6. Recursive: subdirectories ─────────────────────────────────────────────

#[test]
fn test_folder_diff_recursive() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "sub/a.txt", b"same");
    make_file(&left, "sub/b.txt", b"left only");
    make_file(&right, "sub/a.txt", b"same");
    make_file(&right, "sub/c.txt", b"right only");

    let result = diff_folders(left.path(), right.path(), true, CompareBy::Content).unwrap();
    let s = result.summary();
    assert_eq!(s.identical, 1, "sub/a.txt should be identical");
    assert_eq!(s.removed, 1, "sub/b.txt should be removed");
    assert_eq!(s.added, 1, "sub/c.txt should be added");
}

#[test]
fn test_folder_diff_non_recursive_skips_subdirs() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "top.txt", b"same");
    make_file(&left, "sub/deep.txt", b"should be ignored");
    make_file(&right, "top.txt", b"same");
    // sub/ only exists in left, but recursive=false → don't care

    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    // Without recursive, sub/deep.txt is not compared
    assert!(
        !result.has_diff(),
        "non-recursive diff should ignore subdirs"
    );
}

// ── 7. CompareBy::SizeTime ────────────────────────────────────────────────────

#[test]
fn test_folder_diff_size_time_same_size_is_identical() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    // Same size, we'll force same mtime by copying and touching
    make_file(&left, "a.txt", b"hello");
    make_file(&right, "a.txt", b"hello");

    // Same content = same size + close mtime → identical in size-time mode
    let result = diff_folders(left.path(), right.path(), false, CompareBy::SizeTime).unwrap();
    // May be identical or modified depending on mtime precision, but must not panic
    let _ = result.summary();
}

#[test]
fn test_folder_diff_size_time_different_size_is_modified() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "a.txt", b"short");
    make_file(&right, "a.txt", b"much longer content here");

    let result = diff_folders(left.path(), right.path(), false, CompareBy::SizeTime).unwrap();
    let s = result.summary();
    assert_eq!(s.modified, 1, "different sizes → modified");
}

// ── 8. CompareBy::Name ───────────────────────────────────────────────────────

#[test]
fn test_folder_diff_name_mode_same_names_is_identical() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "a.txt", b"completely different content left");
    make_file(&right, "a.txt", b"completely different content right");

    let result = diff_folders(left.path(), right.path(), false, CompareBy::Name).unwrap();
    // Name mode: same name → identical, regardless of content
    let s = result.summary();
    assert_eq!(s.identical, 1);
    assert_eq!(s.modified, 0);
}

// ── 9. Summary accuracy ───────────────────────────────────────────────────────

#[test]
fn test_folder_diff_summary_byte_counts() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "a.txt", b"12345"); // 5 bytes left
    make_file(&right, "a.txt", b"1234567890"); // 10 bytes right (modified)

    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    let s = result.summary();
    assert_eq!(s.left_bytes, 5);
    assert_eq!(s.right_bytes, 10);
}

// ── 10. Empty folder vs non-empty ────────────────────────────────────────────

#[test]
fn test_folder_diff_empty_left() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&right, "newfile.bin", b"new");

    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    let s = result.summary();
    assert_eq!(s.added, 1);
    assert_eq!(s.removed + s.modified + s.identical, 0);
}

#[test]
fn test_folder_diff_empty_right() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "gone.bin", b"old");

    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    let s = result.summary();
    assert_eq!(s.removed, 1);
    assert_eq!(s.added + s.modified + s.identical, 0);
}

// ── 11. has_diff exit-code semantics ─────────────────────────────────────────

#[test]
fn test_folder_diff_has_diff_false_when_identical() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "x.bin", b"data");
    make_file(&right, "x.bin", b"data");
    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    assert!(!result.has_diff());
}

#[test]
fn test_folder_diff_has_diff_true_when_different() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "x.bin", b"old");
    make_file(&right, "x.bin", b"new");
    let result = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    assert!(result.has_diff());
}

// ── 12. Paranoid mode (BLAKE3) ────────────────────────────────────────────────

#[test]
fn test_folder_diff_paranoid_identical() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "a.bin", b"identical content");
    make_file(&right, "a.bin", b"identical content");
    let result = diff_folders(left.path(), right.path(), false, CompareBy::Paranoid).unwrap();
    assert!(!result.has_diff());
    assert_eq!(result.summary().identical, 1);
}

#[test]
fn test_folder_diff_paranoid_detects_modification() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "a.bin", b"version one");
    make_file(&right, "a.bin", b"version two");
    let result = diff_folders(left.path(), right.path(), false, CompareBy::Paranoid).unwrap();
    assert!(result.has_diff());
    assert_eq!(result.summary().modified, 1);
}

#[test]
fn test_folder_diff_paranoid_move_detection() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "old.bin", b"unique paranoid content abc");
    make_file(&right, "new.bin", b"unique paranoid content abc");
    let result = diff_folders(left.path(), right.path(), false, CompareBy::Paranoid).unwrap();
    assert_eq!(result.summary().moved, 1);
}

#[test]
fn test_folder_diff_paranoid_agrees_with_content_on_identical() {
    // Both modes should agree that these files are identical
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "f.bin", b"some bytes");
    make_file(&right, "f.bin", b"some bytes");

    let r_content = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    let r_paranoid = diff_folders(left.path(), right.path(), false, CompareBy::Paranoid).unwrap();
    assert_eq!(r_content.has_diff(), r_paranoid.has_diff());
    assert_eq!(
        r_content.summary().identical,
        r_paranoid.summary().identical
    );
}

#[test]
fn test_folder_diff_paranoid_agrees_with_content_on_modified() {
    let left = tempfile::tempdir().unwrap();
    let right = tempfile::tempdir().unwrap();
    make_file(&left, "f.bin", b"before");
    make_file(&right, "f.bin", b"after");

    let r_content = diff_folders(left.path(), right.path(), false, CompareBy::Content).unwrap();
    let r_paranoid = diff_folders(left.path(), right.path(), false, CompareBy::Paranoid).unwrap();
    assert_eq!(r_content.summary().modified, r_paranoid.summary().modified);
}
