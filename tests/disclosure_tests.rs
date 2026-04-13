use blazehash::disclosure::{generate_selective_proof, verify_selective_proof, SelectiveProof};
use blazehash::merkle::merkle_root;

fn sample_entries() -> Vec<(String, String, String)> {
    vec![
        ("sha256".into(), "abc/secret.txt".into(),  "aaaa".repeat(16)),
        ("sha256".into(), "abc/evidence.bin".into(), "bbbb".repeat(16)),
        ("sha256".into(), "abc/notes.txt".into(),   "cccc".repeat(16)),
    ]
}

#[test]
fn test_selective_proof_reveals_only_requested_paths() {
    let entries = sample_entries();
    let proof = generate_selective_proof(&entries, &["abc/evidence.bin"]).unwrap();
    assert_eq!(proof.disclosed.len(), 1);
    assert_eq!(proof.disclosed[0].path, "abc/evidence.bin");
    let root = merkle_root(&entries).unwrap();
    assert_eq!(proof.root, root);
}

#[test]
fn test_selective_proof_verifies_successfully() {
    let entries = sample_entries();
    let proof = generate_selective_proof(&entries, &["abc/evidence.bin"]).unwrap();
    assert!(verify_selective_proof(&proof).unwrap());
}

#[test]
fn test_selective_proof_tampered_hash_fails() {
    let entries = sample_entries();
    let mut proof = generate_selective_proof(&entries, &["abc/evidence.bin"]).unwrap();
    proof.disclosed[0].sha256 = "0".repeat(64);
    assert!(!verify_selective_proof(&proof).unwrap());
}

#[test]
fn test_selective_proof_multiple_paths() {
    let entries = sample_entries();
    let proof = generate_selective_proof(&entries, &["abc/evidence.bin", "abc/notes.txt"]).unwrap();
    assert_eq!(proof.disclosed.len(), 2);
    assert!(verify_selective_proof(&proof).unwrap());
}

#[test]
fn test_selective_proof_unknown_path_errors() {
    let entries = sample_entries();
    let result = generate_selective_proof(&entries, &["nonexistent.bin"]);
    assert!(result.is_err());
}

#[test]
fn test_membership_proof_proves_hash_exists_without_revealing_path() {
    use blazehash::disclosure::{prove_hash_membership, verify_membership_proof};
    let entries = sample_entries();
    let target_hash = "bbbb".repeat(16); // evidence.bin's hash
    let proof = prove_hash_membership(&entries, &target_hash).unwrap();
    // Proof MUST NOT contain the file path
    let json = serde_json::to_string(&proof).unwrap();
    assert!(!json.contains("evidence.bin"), "path must not appear in proof JSON");
    // But verification must pass
    assert!(verify_membership_proof(&proof, &target_hash).unwrap());
}

#[test]
fn test_membership_proof_wrong_hash_fails() {
    use blazehash::disclosure::{prove_hash_membership, verify_membership_proof};
    let entries = sample_entries();
    let proof = prove_hash_membership(&entries, &"bbbb".repeat(16)).unwrap();
    assert!(!verify_membership_proof(&proof, &"dead".repeat(16)).unwrap());
}

#[test]
fn test_selective_proof_odd_leaf_count() {
    // 4 entries → even leaves, verify the boundary case too
    let entries = vec![
        ("sha256".into(), "a.bin".into(), "aaaa".repeat(16)),
        ("sha256".into(), "b.bin".into(), "bbbb".repeat(16)),
        ("sha256".into(), "c.bin".into(), "cccc".repeat(16)),
        ("sha256".into(), "d.bin".into(), "dddd".repeat(16)),
    ];
    // Request last entry to exercise odd-position proof path
    let proof = generate_selective_proof(&entries, &["d.bin"]).unwrap();
    assert!(verify_selective_proof(&proof).unwrap());
}

#[test]
fn test_selective_proof_two_entries() {
    let entries = vec![
        ("sha256".into(), "x.bin".into(), "eeee".repeat(16)),
        ("sha256".into(), "y.bin".into(), "ffff".repeat(16)),
    ];
    let proof = generate_selective_proof(&entries, &["x.bin"]).unwrap();
    assert!(verify_selective_proof(&proof).unwrap());
    let root = merkle_root(&entries).unwrap();
    assert_eq!(proof.root, root);
}
