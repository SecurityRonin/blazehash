use blazehash::algorithm::Algorithm;
use std::str::FromStr;

#[test]
fn parse_blake3() {
    let algo = Algorithm::from_str("blake3").unwrap();
    assert_eq!(algo, Algorithm::Blake3);
}

#[test]
fn parse_sha256() {
    let algo = Algorithm::from_str("sha256").unwrap();
    assert_eq!(algo, Algorithm::Sha256);
    let algo2 = Algorithm::from_str("sha-256").unwrap();
    assert_eq!(algo2, Algorithm::Sha256);
}

#[test]
fn parse_sha1() {
    let algo = Algorithm::from_str("sha1").unwrap();
    assert_eq!(algo, Algorithm::Sha1);
    let algo2 = Algorithm::from_str("sha-1").unwrap();
    assert_eq!(algo2, Algorithm::Sha1);
}

#[test]
fn parse_md5() {
    let algo = Algorithm::from_str("md5").unwrap();
    assert_eq!(algo, Algorithm::Md5);
}

#[test]
fn parse_sha512() {
    let algo = Algorithm::from_str("sha512").unwrap();
    assert_eq!(algo, Algorithm::Sha512);
}

#[test]
fn parse_sha3_256() {
    let algo = Algorithm::from_str("sha3-256").unwrap();
    assert_eq!(algo, Algorithm::Sha3_256);
}

#[test]
fn parse_tiger() {
    let algo = Algorithm::from_str("tiger").unwrap();
    assert_eq!(algo, Algorithm::Tiger);
}

#[test]
fn parse_whirlpool() {
    let algo = Algorithm::from_str("whirlpool").unwrap();
    assert_eq!(algo, Algorithm::Whirlpool);
}

#[test]
fn parse_invalid_algorithm() {
    assert!(Algorithm::from_str("xxhash").is_err());
}

#[test]
fn algorithm_display_roundtrips() {
    for algo in Algorithm::all() {
        let s = algo.to_string();
        let parsed = Algorithm::from_str(&s).unwrap();
        assert_eq!(*algo, parsed);
    }
}

#[test]
fn default_algorithm_is_blake3() {
    assert_eq!(Algorithm::default(), Algorithm::Blake3);
}

use blazehash::algorithm::hash_bytes;

#[test]
fn hash_bytes_blake3_known_vector() {
    let hash = hash_bytes(Algorithm::Blake3, b"hello world");
    assert_eq!(hash, "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
}

#[test]
fn hash_bytes_sha256_known_vector() {
    let hash = hash_bytes(Algorithm::Sha256, b"hello world");
    assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

#[test]
fn hash_bytes_md5_known_vector() {
    let hash = hash_bytes(Algorithm::Md5, b"hello world");
    assert_eq!(hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
}

#[test]
fn hash_bytes_sha1_known_vector() {
    let hash = hash_bytes(Algorithm::Sha1, b"hello world");
    assert_eq!(hash, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
}

#[test]
fn hash_bytes_sha512_known_vector() {
    let hash = hash_bytes(Algorithm::Sha512, b"hello world");
    assert_eq!(hash, "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
}

#[test]
fn hash_bytes_empty_input() {
    for algo in Algorithm::all() {
        let hash = hash_bytes(*algo, b"");
        assert!(!hash.is_empty(), "empty hash for {:?}", algo);
    }
}

#[test]
fn hash_bytes_sha3_256_known_vector() {
    let hash = hash_bytes(Algorithm::Sha3_256, b"hello world");
    // SHA3-256 of "hello world"
    assert_eq!(hash, "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938");
}

#[test]
fn hash_bytes_tiger_known_vector() {
    let hash = hash_bytes(Algorithm::Tiger, b"hello world");
    assert!(!hash.is_empty());
    assert_eq!(hash.len(), 48); // Tiger produces 192-bit (24 byte = 48 hex chars)
}

#[test]
fn hash_bytes_whirlpool_known_vector() {
    let hash = hash_bytes(Algorithm::Whirlpool, b"hello world");
    assert!(!hash.is_empty());
    assert_eq!(hash.len(), 128); // Whirlpool produces 512-bit (64 byte = 128 hex chars)
}

#[test]
fn parse_algorithm_case_insensitive() {
    assert_eq!(Algorithm::from_str("BLAKE3").unwrap(), Algorithm::Blake3);
    assert_eq!(Algorithm::from_str("SHA256").unwrap(), Algorithm::Sha256);
    assert_eq!(Algorithm::from_str("Sha-256").unwrap(), Algorithm::Sha256);
    assert_eq!(Algorithm::from_str("MD5").unwrap(), Algorithm::Md5);
    assert_eq!(Algorithm::from_str("SHA3-256").unwrap(), Algorithm::Sha3_256);
    assert_eq!(Algorithm::from_str("SHA3_256").unwrap(), Algorithm::Sha3_256);
    assert_eq!(Algorithm::from_str("TIGER").unwrap(), Algorithm::Tiger);
    assert_eq!(Algorithm::from_str("WHIRLPOOL").unwrap(), Algorithm::Whirlpool);
    assert_eq!(Algorithm::from_str("SHA512").unwrap(), Algorithm::Sha512);
    assert_eq!(Algorithm::from_str("SHA-1").unwrap(), Algorithm::Sha1);
}

#[test]
fn parse_algorithm_error_message_contains_name() {
    let err = Algorithm::from_str("xxhash").unwrap_err();
    assert!(err.to_string().contains("xxhash"));
}

#[test]
fn hashdeep_name_matches_display() {
    for algo in Algorithm::all() {
        assert_eq!(algo.hashdeep_name(), &algo.to_string());
    }
}

#[test]
fn algorithm_all_returns_all_variants() {
    let all = Algorithm::all();
    assert_eq!(all.len(), 8);
    // Check all unique
    let mut seen = std::collections::HashSet::new();
    for algo in all {
        assert!(seen.insert(algo));
    }
}
