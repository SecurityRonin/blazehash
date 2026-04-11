use assert_cmd::Command;

#[test]
fn test_looks_like_manifest_hashdeep() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("hashes.hash");
    std::fs::write(&f, "%%%% BLAZEHASH-1.0\n%%%% size,blake3,filename\n##\n5,abc,/f.bin\n")
        .unwrap();
    assert!(blazehash::manifest_loader::looks_like_manifest(&f));
}

#[test]
fn test_looks_like_manifest_json() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("hashes.json");
    std::fs::write(
        &f,
        r#"[{"filename":"/a.bin","hashes":{"blake3":"aa"},"size":1}]"#,
    )
    .unwrap();
    assert!(blazehash::manifest_loader::looks_like_manifest(&f));
}

#[test]
fn test_looks_like_manifest_jsonl() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("hashes.jsonl");
    std::fs::write(
        &f,
        "{\"filename\":\"/a.bin\",\"hashes\":{\"sha256\":\"bb\"},\"size\":2}\n",
    )
    .unwrap();
    assert!(blazehash::manifest_loader::looks_like_manifest(&f));
}

#[test]
fn test_looks_like_manifest_csv() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("hashes.csv");
    std::fs::write(&f, "size,blake3,sha256,filename\n5,aa,bb,/f.bin\n").unwrap();
    assert!(blazehash::manifest_loader::looks_like_manifest(&f));
}

#[test]
fn test_looks_like_manifest_non_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("readme.txt");
    std::fs::write(&f, "This is just a plain text file, not a manifest.\n").unwrap();
    assert!(!blazehash::manifest_loader::looks_like_manifest(&f));
}

#[test]
fn test_load_json_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("hashes.json");
    std::fs::write(
        &manifest,
        r#"[
  {
    "filename": "/evidence/doc.pdf",
    "hashes": {"blake3": "aabbcc"},
    "size": 42
  }
]"#,
    )
    .unwrap();

    let records = blazehash::manifest_loader::load_manifest(&manifest).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].size, 42);
    // Check that blake3 hash is present
    let hash_val = records[0].hashes.values().next().expect("no hash");
    assert_eq!(hash_val, "aabbcc");
}

#[test]
fn test_load_jsonl_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("hashes.jsonl");
    std::fs::write(
        &manifest,
        "{\"filename\":\"/evidence/a.bin\",\"hashes\":{\"sha256\":\"deadbeef\"},\"size\":10}\n\
         {\"filename\":\"/evidence/b.bin\",\"hashes\":{\"sha256\":\"cafebabe\"},\"size\":20}\n",
    )
    .unwrap();

    let records = blazehash::manifest_loader::load_manifest(&manifest).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].size, 10);
    assert_eq!(records[1].size, 20);
}

#[test]
fn test_load_csv_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("hashes.csv");
    std::fs::write(
        &manifest,
        "size,blake3,sha256,filename\n\
         13,8e3d,a1ff,/evidence/file.txt\n",
    )
    .unwrap();

    let records = blazehash::manifest_loader::load_manifest(&manifest).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].size, 13);
    assert_eq!(
        records[0].path,
        std::path::PathBuf::from("/evidence/file.txt")
    );
}

#[test]
fn test_manifest_json_roundtrip() {
    // Hash a file, write JSON, load it back — all fields survive round-trip
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("sample.txt");
    std::fs::write(&file, b"hello world").unwrap();
    let manifest = dir.path().join("out.json");

    Command::cargo_bin("blazehash")
        .unwrap()
        .args([
            "-c",
            "blake3",
            "--format",
            "json",
            "-o",
            manifest.to_str().unwrap(),
            file.to_str().unwrap(),
        ])
        .assert()
        .success();

    let records = blazehash::manifest_loader::load_manifest(&manifest).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].size, 11); // "hello world" = 11 bytes
}
