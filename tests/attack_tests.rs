use blazehash::attack::lookup_attack;

#[test]
fn test_unknown_rule_returns_none() {
    assert!(lookup_attack("SomeRandomRule").is_none());
    assert!(lookup_attack("").is_none());
    // Prefix-table lookup removed with forensicnomicon dep.
    assert!(lookup_attack("RAT_QuasarRat").is_none());
    assert!(lookup_attack("Ransomware_LockBit").is_none());
}

#[cfg(feature = "yara")]
#[test]
fn test_stix_output_includes_attack_extension_when_yara_tag_is_technique_id() {
    use blazehash::algorithm::Algorithm;
    use blazehash::format::write_stix;
    use blazehash::hash::FileHashResult;
    use std::collections::HashMap;
    use std::path::PathBuf;

    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "a".repeat(64));
    let result = FileHashResult {
        path: PathBuf::from("malware.bin"),
        hashes,
        size: 1024,
        entropy: None,
        yara_matches: Some(vec![blazehash::yara_scan::YaraMatch {
            rule_name: "RAT_QuasarRat".to_string(),
            tags: vec!["T1219".to_string()],
        }]),
    };
    let mut buf = Vec::new();
    write_stix(&mut buf, &[result], &[Algorithm::Blake3]).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let bundle_str = json.to_string();
    assert!(
        bundle_str.contains("T1219") || bundle_str.contains("x-mitre-attack"),
        "STIX bundle missing ATT&CK annotation: {bundle_str}"
    );
}
