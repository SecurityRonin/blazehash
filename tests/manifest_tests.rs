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

#[test]
fn parse_header_empty_string_returns_error() {
    let err = parse_header("");
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("missing header"));
}

#[test]
fn parse_header_missing_column_line() {
    let err = parse_header("%%%% HASHDEEP-1.0\n");
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("missing column line"));
}

#[test]
fn parse_header_missing_filename_column() {
    let err = parse_header("%%%% HASHDEEP-1.0\n%%%% size,blake3\n");
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("missing filename column"));
}

#[test]
fn parse_header_unknown_algorithm_returns_error() {
    let err = parse_header("%%%% HASHDEEP-1.0\n%%%% size,xxhash,filename\n");
    assert!(err.is_err());
}

#[test]
fn parse_header_many_algorithms() {
    let input = "%%%% HASHDEEP-1.0\n%%%% size,blake3,sha256,md5,sha1,filename\n";
    let algos = parse_header(input).unwrap();
    assert_eq!(algos, vec![Algorithm::Blake3, Algorithm::Sha256, Algorithm::Md5, Algorithm::Sha1]);
}

#[test]
fn write_header_contains_version_comment() {
    let mut buf = Vec::new();
    write_header(&mut buf, &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.contains("## Invoked from: blazehash v"));
    assert!(output.contains("##\n"));
}

#[test]
fn write_record_zero_size_file() {
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262".to_string());
    let result = FileHashResult {
        path: PathBuf::from("/empty.txt"),
        size: 0,
        hashes,
    };

    let mut buf = Vec::new();
    write_record(&mut buf, &result, &[Algorithm::Blake3]).unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.starts_with("0,"));
}

#[test]
fn parse_header_not_hashdeep_file() {
    let err = parse_header("this is not a hashdeep file\nsome other content\n");
    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("not a hashdeep file"));
}
