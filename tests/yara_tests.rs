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
        assert_eq!(hits[0].rule_name, "test_match");
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

#[cfg(feature = "yara")]
mod yara_tag_tests {
    use blazehash::yara_scan::{YaraMatch, YaraScanner};
    use tempfile::TempDir;
    use std::fs;

    fn write_rule(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let path = dir.path().join("test.yar");
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_yara_match_has_rule_name() {
        let dir = TempDir::new().unwrap();
        let rules = write_rule(&dir, r#"
rule test_rule {
    strings:
        $a = "hello"
    condition:
        $a
}"#);
        let scanner = YaraScanner::new(&rules).unwrap();
        let matches = scanner.scan(b"hello world").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "test_rule");
    }

    #[test]
    fn test_yara_match_has_tags() {
        let dir = TempDir::new().unwrap();
        // Rule with ATT&CK technique tags
        let rules = write_rule(&dir, r#"
rule tagged_rule : T1486 T1059 {
    strings:
        $a = "ransom"
    condition:
        $a
}"#);
        let scanner = YaraScanner::new(&rules).unwrap();
        let matches = scanner.scan(b"pay ransom now").unwrap();
        assert_eq!(matches.len(), 1);
        let tags = &matches[0].tags;
        assert!(tags.contains(&"T1486".to_string()), "should have T1486 tag, got: {tags:?}");
        assert!(tags.contains(&"T1059".to_string()), "should have T1059 tag, got: {tags:?}");
    }

    #[test]
    fn test_attack_from_tag_takes_priority_over_prefix() {
        use blazehash::attack::lookup_attack_for_match;
        // A match with a T1234 tag should use the tag, not the prefix table
        let m = YaraMatch {
            rule_name: "ransomware_test".to_string(),
            tags: vec!["T1027".to_string()],  // tag says T1027, prefix says T1486
        };
        let result = lookup_attack_for_match(&m);
        assert!(result.is_some());
        // Tag T1027 takes priority over prefix-derived T1486
        assert_eq!(result.unwrap().technique_id, "T1027");
    }

    #[test]
    fn test_attack_falls_back_to_prefix_when_no_technique_tag() {
        use blazehash::attack::lookup_attack_for_match;
        // No T-prefixed tag → fall back to name prefix
        let m = YaraMatch {
            rule_name: "ransomware_conti".to_string(),
            tags: vec!["malware".to_string()],  // no T#### tag
        };
        let result = lookup_attack_for_match(&m);
        assert!(result.is_some());
        assert_eq!(result.unwrap().technique_id, "T1486");  // from prefix table
    }

    #[test]
    fn test_attack_no_match_when_no_tag_and_unknown_prefix() {
        use blazehash::attack::lookup_attack_for_match;
        let m = YaraMatch {
            rule_name: "APT_Lazarus_Unknown".to_string(),
            tags: vec![],
        };
        let result = lookup_attack_for_match(&m);
        assert!(result.is_none());
    }
}
