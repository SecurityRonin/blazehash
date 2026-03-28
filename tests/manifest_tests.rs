use blazehash::algorithm::Algorithm;
use blazehash::manifest::{write_header, write_record, parse_header};
use blazehash::hash::FileHashResult;
use std::collections::HashMap;
use std::path::PathBuf;

#[test]
fn write_header_default_blake3() {
    let mut buf = Vec::new();
    write_header(&mut buf, &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.starts_with("%%%% HASHDEEP-1.0\n"));
    assert!(output.contains("%%%% size,blake3,filename\n"));
}

#[test]
fn write_header_multiple_algorithms() {
    let mut buf = Vec::new();
    write_header(&mut buf, &[Algorithm::Md5, Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("%%%% size,md5,sha256,filename\n"));
}

#[test]
fn write_record_single_algorithm() {
    let mut hashes = HashMap::new();
    hashes.insert(
        Algorithm::Blake3,
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24".to_string(),
    );
    let result = FileHashResult {
        path: PathBuf::from("/home/user/test.txt"),
        size: 11,
        hashes,
    };

    let mut buf = Vec::new();
    write_record(&mut buf, &result, &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert_eq!(
        output,
        "11,d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24,/home/user/test.txt\n"
    );
}

#[test]
fn write_record_multiple_algorithms() {
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Md5, "5eb63bbbe01eeed093cb22bb8f5acdc3".to_string());
    hashes.insert(
        Algorithm::Sha256,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
    );
    let result = FileHashResult {
        path: PathBuf::from("/home/user/test.txt"),
        size: 11,
        hashes,
    };

    let mut buf = Vec::new();
    write_record(&mut buf, &result, &[Algorithm::Md5, Algorithm::Sha256]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert_eq!(
        output,
        "11,5eb63bbbe01eeed093cb22bb8f5acdc3,b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9,/home/user/test.txt\n"
    );
}

#[test]
fn parse_header_extracts_algorithms() {
    let input = "%%%% HASHDEEP-1.0\n%%%% size,md5,sha256,filename\n## Invoked from: /home\n";
    let algos = parse_header(input).unwrap();
    assert_eq!(algos, vec![Algorithm::Md5, Algorithm::Sha256]);
}

#[test]
fn parse_header_single_algorithm() {
    let input = "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n";
    let algos = parse_header(input).unwrap();
    assert_eq!(algos, vec![Algorithm::Blake3]);
}

#[test]
fn filename_with_comma_preserved() {
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abcd1234".to_string());
    let result = FileHashResult {
        path: PathBuf::from("/home/user/file,with,commas.txt"),
        size: 42,
        hashes,
    };

    let mut buf = Vec::new();
    write_record(&mut buf, &result, &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert_eq!(output, "42,abcd1234,/home/user/file,with,commas.txt\n");
}

#[test]
fn write_record_missing_algorithm_returns_error() {
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "abcd1234".to_string());
    // Sha256 is NOT in the hashes map
    let result = FileHashResult {
        path: PathBuf::from("/test.txt"),
        size: 11,
        hashes,
    };

    let mut buf = Vec::new();
    let err = write_record(&mut buf, &result, &[Algorithm::Blake3, Algorithm::Sha256]);
    assert!(err.is_err(), "should error when algorithm hash is missing");
}
