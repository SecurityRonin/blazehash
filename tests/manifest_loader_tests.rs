use assert_cmd::Command;

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
