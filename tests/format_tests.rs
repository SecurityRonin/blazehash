use blazehash::algorithm::Algorithm;
use blazehash::format::{write_csv, write_dfxml, write_json, write_jsonl, write_sumfile};
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
        entropy: None,
        #[cfg(feature = "yara")]
        yara_matches: None,
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
        entropy: None,
        #[cfg(feature = "yara")]
        yara_matches: None,
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
        entropy: None,
        #[cfg(feature = "yara")]
        yara_matches: None,
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
fn dfxml_output_has_root_element() {
    let results = vec![sample_result()];
    let algos = vec![Algorithm::Blake3, Algorithm::Sha256];
    let mut buf = Vec::new();
    write_dfxml(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("<dfxml"));
    assert!(output.contains("</dfxml>"));
    assert!(output.contains("<fileobject>"));
    assert!(output.contains("<filesize>11</filesize>"));
}

#[test]
fn dfxml_output_has_hash_digests() {
    let results = vec![sample_result()];
    let algos = vec![Algorithm::Blake3];
    let mut buf = Vec::new();
    write_dfxml(&mut buf, &results, &algos).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("hashdigest type='BLAKE3'")
            || output.contains("hashdigest type='blake3'")
            || output.contains("hashdigest")
    );
}

#[test]
fn dfxml_empty_results() {
    let mut buf = Vec::new();
    write_dfxml(&mut buf, &[], &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("<dfxml"));
    assert!(!output.contains("<fileobject>"));
}

#[test]
fn sumfile_output_hash_two_spaces_path() {
    let mut hashes = std::collections::HashMap::new();
    hashes.insert(
        Algorithm::Sha256,
        "abc123def456abc123def456abc123def456abc123def456abc123def456abc1".to_string(),
    );
    let result = FileHashResult {
        path: std::path::PathBuf::from("/evidence/test.bin"),
        size: 42,
        hashes,
        entropy: None,
        #[cfg(feature = "yara")]
        yara_matches: None,
    };
    let mut buf = Vec::new();
    write_sumfile(&mut buf, &[result], &[Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(
        output.contains("  /evidence/test.bin"),
        "expected two-space separator"
    );
}

#[test]
fn sumfile_error_on_multiple_algorithms() {
    let mut buf = Vec::new();
    let result = sample_result();
    let err = write_sumfile(&mut buf, &[result], &[Algorithm::Blake3, Algorithm::Sha256]);
    assert!(
        err.is_err(),
        "sumfile should error with multiple algorithms"
    );
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_output_queryable() {
    use blazehash::algorithm::Algorithm;
    use blazehash::format::write_sqlite;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("out.db");

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "deadbeef".to_string());
    let result = FileHashResult {
        path: PathBuf::from("/evidence/doc.pdf"),
        size: 42,
        hashes,
        entropy: Some(6.5),
        #[cfg(feature = "yara")]
        yara_matches: None,
    };

    write_sqlite(&db_path, &[result], &[Algorithm::Blake3]).unwrap();
    assert!(db_path.exists());

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let (path, size, blake3, entropy): (String, i64, String, f64) = conn
        .query_row(
            "SELECT path, size, blake3, entropy FROM files WHERE path = '/evidence/doc.pdf'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(path, "/evidence/doc.pdf");
    assert_eq!(size, 42);
    assert_eq!(blake3, "deadbeef");
    assert!((entropy - 6.5).abs() < 1e-6);
}

#[cfg(feature = "parquet-output")]
#[test]
fn parquet_output_creates_file() {
    use blazehash::algorithm::Algorithm;
    use blazehash::format::write_parquet;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.parquet");

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abc".to_string());
    let result = FileHashResult {
        path: PathBuf::from("/f.bin"),
        size: 5,
        hashes,
        entropy: None,
        #[cfg(feature = "yara")]
        yara_matches: None,
    };

    write_parquet(&out, &[result], &[Algorithm::Blake3]).unwrap();
    assert!(out.exists(), "parquet file should be created");
    assert!(
        out.metadata().unwrap().len() > 0,
        "parquet file should not be empty"
    );
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
        entropy: None,
        #[cfg(feature = "yara")]
        yara_matches: None,
    };

    let mut buf = Vec::new();
    write_json(&mut buf, &[result], &[Algorithm::Blake3, Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
    // blake3 present, sha256 absent (silently skipped)
    assert!(parsed[0]["hashes"].get("blake3").is_some());
    assert!(parsed[0]["hashes"].get("sha256").is_none());
}

// ---- Task 2: --entropy column ----

#[test]
fn csv_entropy_column_present_when_set() {
    use blazehash::algorithm::Algorithm;
    use blazehash::format::write_csv;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abc".to_string());
    let r = FileHashResult {
        path: PathBuf::from("/f.bin"),
        size: 10,
        hashes,
        entropy: Some(7.9),
        #[cfg(feature = "yara")]
        yara_matches: None,
    };
    let algos = vec![Algorithm::Blake3];
    let mut buf = Vec::new();
    write_csv(&mut buf, &[r], &algos).unwrap();
    let out = String::from_utf8(buf).unwrap();
    assert!(
        out.contains("entropy"),
        "header must contain entropy column"
    );
    assert!(out.contains("7.9"), "data row must contain entropy value");
}

#[test]
fn json_entropy_field_present_when_set() {
    use blazehash::algorithm::Algorithm;
    use blazehash::format::write_json;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abc".to_string());
    let r = FileHashResult {
        path: PathBuf::from("/f.bin"),
        size: 10,
        hashes,
        entropy: Some(3.5),
        #[cfg(feature = "yara")]
        yara_matches: None,
    };
    let mut buf = Vec::new();
    write_json(&mut buf, &[r], &[Algorithm::Blake3]).unwrap();
    let out = String::from_utf8(buf).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(
        v[0].get("entropy").is_some(),
        "JSON must include entropy field"
    );
    assert_eq!(v[0]["entropy"], 3.5);
}

#[cfg(feature = "duckdb-output")]
#[test]
fn duckdb_output_creates_file() {
    use blazehash::algorithm::Algorithm;
    use blazehash::format::write_duckdb;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let out = dir.path().join("manifest.duckdb");

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abc123".to_string());

    let results = vec![FileHashResult {
        path: std::path::PathBuf::from("/tmp/test.bin"),
        size: 42,
        hashes,
        entropy: Some(3.5),
        #[cfg(feature = "yara")]
        yara_matches: None,
    }];

    write_duckdb(&out, &results, &[Algorithm::Blake3]).unwrap();
    assert!(out.exists(), "duckdb file should be created");

    // Verify we can read it back
    let conn = duckdb::Connection::open(&out).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[cfg(feature = "duckdb-output")]
#[test]
fn duckdb_output_empty_results() {
    use blazehash::algorithm::Algorithm;
    use blazehash::format::write_duckdb;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let out = dir.path().join("empty.duckdb");
    write_duckdb(&out, &[], &[Algorithm::Blake3]).unwrap();
    assert!(out.exists());
}

// ---- Task 6: STIX 2.1 output ----

#[test]
fn test_stix_output_is_valid_bundle() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let mut hashes = HashMap::new();
    hashes.insert(
        Algorithm::Sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
    );
    let r = FileHashResult {
        path: PathBuf::from("/evidence/malware.exe"),
        size: 4096,
        hashes,
        entropy: None,
        #[cfg(feature = "yara")]
        yara_matches: None,
    };

    let mut buf = Vec::new();
    blazehash::format::write_stix(&mut buf, &[r], &[Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let bundle: serde_json::Value = serde_json::from_str(&output).expect("must be valid JSON");
    assert_eq!(bundle["type"], "bundle");
    assert_eq!(bundle["spec_version"], "2.1");
    let objects = bundle["objects"].as_array().expect("must be array");
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0]["type"], "file");
    assert_eq!(objects[0]["spec_version"], "2.1");
    assert_eq!(
        objects[0]["hashes"]["SHA-256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(objects[0]["size"], 4096);
    assert_eq!(objects[0]["name"], "malware.exe");
    let id = objects[0]["id"].as_str().unwrap();
    assert!(
        id.starts_with("file--"),
        "STIX file SCO id must start with file--"
    );
}

#[test]
fn test_stix_output_multiple_algorithms() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Sha256, "abc123".to_string());
    hashes.insert(Algorithm::Md5, "def456".to_string());
    let r = FileHashResult {
        path: PathBuf::from("/test.bin"),
        size: 100,
        hashes,
        entropy: None,
        #[cfg(feature = "yara")]
        yara_matches: None,
    };

    let mut buf = Vec::new();
    blazehash::format::write_stix(&mut buf, &[r], &[Algorithm::Sha256, Algorithm::Md5]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let bundle: serde_json::Value = serde_json::from_str(&output).unwrap();
    let file_obj = &bundle["objects"][0];
    assert!(file_obj["hashes"]["SHA-256"].is_string());
    assert!(file_obj["hashes"]["MD5"].is_string());
}

// ---- Task 7: ECS NDJSON output ----

#[test]
fn test_ecs_output_has_correct_fields() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let mut hashes = HashMap::new();
    hashes.insert(
        Algorithm::Sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
    );
    let r = FileHashResult {
        path: PathBuf::from("/evidence/file.bin"),
        size: 2048,
        hashes,
        entropy: Some(7.5),
        #[cfg(feature = "yara")]
        yara_matches: None,
    };

    let mut buf = Vec::new();
    blazehash::format::write_ecs(&mut buf, &[r], &[Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let line = output.lines().next().expect("must have at least one line");
    let doc: serde_json::Value = serde_json::from_str(line).expect("must be valid JSON");
    assert!(doc["@timestamp"].is_string(), "must have @timestamp");
    assert_eq!(doc["file"]["path"], "/evidence/file.bin");
    assert_eq!(
        doc["file"]["hash"]["sha256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(doc["file"]["size"], 2048);
}

#[test]
fn test_ecs_output_is_ndjson() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let results: Vec<FileHashResult> = (0..3)
        .map(|i| {
            let mut hashes = HashMap::new();
            hashes.insert(Algorithm::Blake3, format!("hash{i}"));
            FileHashResult {
                path: PathBuf::from(format!("/file{i}.bin")),
                size: i * 100,
                hashes,
                entropy: None,
                #[cfg(feature = "yara")]
                yara_matches: None,
            }
        })
        .collect();

    let mut buf = Vec::new();
    blazehash::format::write_ecs(&mut buf, &results, &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(lines.len(), 3, "3 records must produce 3 NDJSON lines");
    for line in lines {
        serde_json::from_str::<serde_json::Value>(line).expect("each line must be valid JSON");
    }
}

/// sqlite feature must be available standalone (without hashdb).
/// This test verifies write_sqlite is reachable when only `sqlite` is enabled.
#[cfg(feature = "sqlite")]
#[test]
fn sqlite_feature_is_independent_of_hashdb() {
    // write_sqlite is gated on `sqlite` feature, not `hashdb`.
    // If this compiles and runs, the feature split is correct.
    use blazehash::algorithm::Algorithm;
    use blazehash::format::write_sqlite;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("standalone_sqlite.db");

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "cafebabe".to_string());
    let result = FileHashResult {
        path: PathBuf::from("/test/standalone.bin"),
        size: 100,
        hashes,
        entropy: None,
        #[cfg(feature = "yara")]
        yara_matches: None,
    };

    write_sqlite(&db_path, &[result], &[Algorithm::Blake3]).unwrap();
    assert!(
        db_path.exists(),
        "sqlite output must be created under sqlite feature alone"
    );
}
