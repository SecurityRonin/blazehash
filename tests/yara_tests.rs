#[cfg(feature = "yara")]
mod yara_tests {
    use blazehash::yara_scan::YaraScanner;
    use tempfile::tempdir;

    const SIMPLE_RULE: &str = r#"
rule test_match {
    strings:
        $magic = "TESTMAGIC"
    condition:
        $magic
}"#;

    #[test]
    fn test_yara_scanner_compiles_rule() {
        let dir = tempdir().unwrap();
        let rules_file = dir.path().join("rules.yar");
        std::fs::write(&rules_file, SIMPLE_RULE).unwrap();
        assert!(YaraScanner::new(&rules_file).is_ok());
    }

    #[test]
    fn test_yara_scanner_matches_bytes() {
        let dir = tempdir().unwrap();
        let rules_file = dir.path().join("rules.yar");
        std::fs::write(&rules_file, SIMPLE_RULE).unwrap();
        let scanner = YaraScanner::new(&rules_file).unwrap();
        let hits = scanner.scan(b"prefix TESTMAGIC suffix").unwrap();
        assert!(!hits.is_empty(), "should match test_match rule");
        assert_eq!(hits[0], "test_match");
    }

    #[test]
    fn test_yara_scanner_no_match() {
        let dir = tempdir().unwrap();
        let rules_file = dir.path().join("rules.yar");
        std::fs::write(&rules_file, SIMPLE_RULE).unwrap();
        let scanner = YaraScanner::new(&rules_file).unwrap();
        let hits = scanner.scan(b"no magic bytes here").unwrap();
        assert!(hits.is_empty(), "should not match when pattern absent");
    }
}
