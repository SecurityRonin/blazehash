use blazehash::attack::lookup_attack;

#[test]
fn test_rat_prefix_maps_to_t1219() {
    let t = lookup_attack("RAT_QuasarRat").unwrap();
    assert_eq!(t.technique_id, "T1219");
    assert_eq!(t.tactic, "command-and-control");
}

#[test]
fn test_ransomware_prefix_maps_to_t1486() {
    let t = lookup_attack("Ransomware_LockBit").unwrap();
    assert_eq!(t.technique_id, "T1486");
}

#[test]
fn test_cred_dump_maps_to_t1003() {
    let t = lookup_attack("CredDump_Mimikatz").unwrap();
    assert_eq!(t.technique_id, "T1003");
}

#[test]
fn test_unknown_rule_returns_none() {
    assert!(lookup_attack("SomeRandomRule").is_none());
    assert!(lookup_attack("").is_none());
}

#[test]
fn test_lookup_is_case_insensitive() {
    // "rat_" lowercase should still match
    let t = lookup_attack("rat_tool");
    assert!(t.is_some());
    assert_eq!(t.unwrap().technique_id, "T1219");
}

#[cfg(feature = "yara")]
#[test]
fn test_stix_output_includes_attack_extension_when_yara_matches() {
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
        yara_matches: Some(vec!["RAT_QuasarRat".to_string()]),
    };
    let mut buf = Vec::new();
    write_stix(&mut buf, &[result], &[Algorithm::Blake3]).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let bundle_str = json.to_string();
    // The STIX bundle should include T1219 annotation
    assert!(
        bundle_str.contains("T1219") || bundle_str.contains("x-mitre-attack"),
        "STIX bundle missing ATT&CK annotation: {bundle_str}"
    );
}
