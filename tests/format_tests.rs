use blazehash::algorithm::Algorithm;
use blazehash::format::{write_csv, write_json, write_jsonl};
use blazehash::hash::FileHashResult;
use std::collections::HashMap;
use std::path::PathBuf;

fn sample_result() -> FileHashResult {
    let mut hashes = HashMap::new();
    hashes.insert(
        Algorithm::Blake3,
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24".to_string(),
    );
    hashes.insert(
        Algorithm::Sha256,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
    );
    FileHashResult {
        path: PathBuf::from("/evidence/test.txt"),
        size: 11,
        hashes,
    }
}

#[test]
fn csv_output_has_headers() {
    let results = vec![sample_result()];
    let algos = vec![Algorithm::Blake3, Algorithm::Sha256];
    let mut buf = Vec::new();
    write_csv(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.starts_with("size,blake3,sha256,filename\n"));
}

#[test]
fn csv_output_has_data() {
    let results = vec![sample_result()];
    let algos = vec![Algorithm::Blake3, Algorithm::Sha256];
    let mut buf = Vec::new();
    write_csv(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[1].starts_with("11,"));
    assert!(lines[1].ends_with("/evidence/test.txt"));
}

#[test]
fn json_output_is_valid() {
    let results = vec![sample_result()];
    let algos = vec![Algorithm::Blake3];
    let mut buf = Vec::new();
    write_json(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);
}

#[test]
fn jsonl_output_one_per_line() {
    let results = vec![sample_result(), sample_result()];
    let algos = vec![Algorithm::Blake3];
    let mut buf = Vec::new();
    write_jsonl(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
}

#[test]
fn csv_missing_algorithm_returns_error() {
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abcd1234".to_string());
    let result = FileHashResult {
        path: PathBuf::from("/test.txt"),
        size: 11,
        hashes,
    };

    let mut buf = Vec::new();
    let err =
        blazehash::format::write_csv(&mut buf, &[result], &[Algorithm::Blake3, Algorithm::Sha256]);
    assert!(err.is_err(), "should error when algorithm hash is missing");
}

#[test]
fn csv_empty_results() {
    let mut buf = Vec::new();
    write_csv(&mut buf, &[], &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    // Should have header only
    assert_eq!(output.lines().count(), 1);
    assert!(output.starts_with("size,blake3,filename"));
}

#[test]
fn csv_multiple_results() {
    let r1 = sample_result();
    let mut hashes2 = HashMap::new();
    hashes2.insert(Algorithm::Blake3, "aaaa".to_string());
    hashes2.insert(Algorithm::Sha256, "bbbb".to_string());
    let r2 = FileHashResult {
        path: PathBuf::from("/evidence/other.txt"),
        size: 42,
        hashes: hashes2,
    };
    let algos = vec![Algorithm::Blake3, Algorithm::Sha256];
    let mut buf = Vec::new();
    write_csv(&mut buf, &[r1, r2], &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert_eq!(output.lines().count(), 3); // header + 2 data
}

#[test]
fn json_empty_results() {
    let mut buf = Vec::new();
    write_json(&mut buf, &[], &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[test]
fn json_structure_has_expected_fields() {
    let results = vec![sample_result()];
    let algos = vec![Algorithm::Blake3, Algorithm::Sha256];
    let mut buf = Vec::new();
    write_json(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    let entry = &parsed[0];
    assert!(entry.get("filename").is_some());
    assert!(entry.get("size").is_some());
    assert!(entry.get("hashes").is_some());
    assert_eq!(entry["size"], 11);
    assert!(entry["hashes"].get("blake3").is_some());
    assert!(entry["hashes"].get("sha256").is_some());
}

#[test]
fn jsonl_empty_results() {
    let mut buf = Vec::new();
    write_jsonl(&mut buf, &[], &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.is_empty());
}

#[test]
fn json_missing_algorithm_silently_skipped() {
    // json.rs uses `if let Some(hash)` — missing algo is silently omitted
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abcd1234".to_string());
    // Note: Sha256 is NOT in hashes
    let result = FileHashResult {
        path: PathBuf::from("/test.txt"),
        size: 11,
        hashes,
    };

    let mut buf = Vec::new();
    write_json(&mut buf, &[result], &[Algorithm::Blake3, Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    // blake3 present, sha256 absent (silently skipped)
    assert!(parsed[0]["hashes"].get("blake3").is_some());
    assert!(parsed[0]["hashes"].get("sha256").is_none());
}
