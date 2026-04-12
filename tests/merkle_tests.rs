use blazehash::merkle::{build_tree, generate_proof, merkle_root, verify_proof};

#[test]
fn test_merkle_root_single_entry() {
    // Single entry: root == leaf hash
    let entries = vec![(
        "sha256".to_string(),
        "/foo/bar".to_string(),
        "abc123def456".to_string(),
    )];
    let root = merkle_root(&entries).unwrap();
    assert_eq!(root.len(), 64, "root must be 64 hex chars");
}

#[test]
fn test_merkle_root_deterministic() {
    let entries = vec![
        ("sha256".to_string(), "/a".to_string(), "aaa".to_string()),
        ("sha256".to_string(), "/b".to_string(), "bbb".to_string()),
    ];
    let r1 = merkle_root(&entries).unwrap();
    let r2 = merkle_root(&entries).unwrap();
    assert_eq!(r1, r2, "same entries → same root");
}

#[test]
fn test_merkle_root_order_independent() {
    // Canonical ordering: swapping entries gives same root
    let entries_ab = vec![
        ("sha256".to_string(), "/a".to_string(), "aaa".to_string()),
        ("sha256".to_string(), "/b".to_string(), "bbb".to_string()),
    ];
    let entries_ba = vec![
        ("sha256".to_string(), "/b".to_string(), "bbb".to_string()),
        ("sha256".to_string(), "/a".to_string(), "aaa".to_string()),
    ];
    let r_ab = merkle_root(&entries_ab).unwrap();
    let r_ba = merkle_root(&entries_ba).unwrap();
    assert_eq!(r_ab, r_ba, "canonical ordering: insertion order must not matter");
}

#[test]
fn test_merkle_proof_and_verify() {
    let entries = vec![
        ("sha256".to_string(), "/a".to_string(), "aaa".to_string()),
        ("sha256".to_string(), "/b".to_string(), "bbb".to_string()),
        ("sha256".to_string(), "/c".to_string(), "ccc".to_string()),
    ];
    let root = merkle_root(&entries).unwrap();

    // Generate proof for /b
    let proof = generate_proof(&entries, "/b").unwrap();
    assert!(!proof.is_empty(), "proof must have at least one sibling");

    // Verify the proof
    let leaf_sha256 = "bbb";
    let leaf_path = "/b";
    let ok = verify_proof(&root, leaf_path, leaf_sha256, &proof).unwrap();
    assert!(ok, "valid proof must verify");
}

#[test]
fn test_merkle_proof_wrong_hash_fails() {
    let entries = vec![
        ("sha256".to_string(), "/a".to_string(), "aaa".to_string()),
        ("sha256".to_string(), "/b".to_string(), "bbb".to_string()),
    ];
    let root = merkle_root(&entries).unwrap();
    let proof = generate_proof(&entries, "/b").unwrap();

    // Tampered: wrong hash for /b
    let ok = verify_proof(&root, "/b", "WRONG", &proof).unwrap();
    assert!(!ok, "tampered hash must fail proof verification");
}

#[test]
fn test_merkle_single_entry_proof() {
    let entries = vec![(
        "sha256".to_string(),
        "/only".to_string(),
        "deadbeef".to_string(),
    )];
    let root = merkle_root(&entries).unwrap();
    let proof = generate_proof(&entries, "/only").unwrap();
    // Single entry: empty proof, leaf IS the root
    assert!(proof.is_empty(), "single entry has empty proof");
    let ok = verify_proof(&root, "/only", "deadbeef", &proof).unwrap();
    assert!(ok, "single entry proof must verify");
}

// ── CLI tests (Task 5) ────────────────────────────────────────────────────────

use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn test_cli_merkle_root() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("test.hash");
    // Write a simple hashdeep-style manifest with sha256 column
    std::fs::write(
        &manifest,
        "%%%% HASHDEEP-1.0\n%%%% size,sha256,filename\n## Computed by blazehash\n10,abc123def456789abc123def456789abc123def456789abc123def456789ab,/foo/bar\n",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("blazehash").unwrap();
    cmd.arg("merkle").arg(&manifest);
    let output = cmd.assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.trim().len() == 64,
        "merkle root must be 64 hex chars, got: {stdout}"
    );
}

#[test]
fn test_cli_merkle_proof_and_verify() {
    let dir = tempdir().unwrap();
    let manifest = dir.path().join("test.hash");
    let sha256_a = "a".repeat(64);
    let sha256_b = "b".repeat(64);
    let content = format!(
        "%%%% HASHDEEP-1.0\n%%%% size,sha256,filename\n## Computed by blazehash\n1,{sha256_a},/a\n2,{sha256_b},/b\n"
    );
    std::fs::write(&manifest, &content).unwrap();

    // Get root
    let root_out = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("merkle")
        .arg(&manifest)
        .assert()
        .success();
    let root = String::from_utf8(root_out.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // Get proof
    let proof_out = Command::cargo_bin("blazehash")
        .unwrap()
        .arg("merkle-proof")
        .arg(&manifest)
        .arg("--path")
        .arg("/a")
        .assert()
        .success();
    let proof_json = String::from_utf8(proof_out.get_output().stdout.clone()).unwrap();
    // proof is a JSON array of hex strings
    assert!(proof_json.contains('['), "proof output must be JSON array");

    // Verify
    Command::cargo_bin("blazehash")
        .unwrap()
        .arg("merkle-verify")
        .arg("--root")
        .arg(&root)
        .arg("--path")
        .arg("/a")
        .arg("--sha256")
        .arg(&sha256_a)
        .arg("--proof")
        .arg(proof_json.trim())
        .assert()
        .success();
}
