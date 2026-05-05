use blazehash::attack::lookup_attack;

#[test]
fn test_unknown_rule_returns_none() {
    assert!(lookup_attack("SomeRandomRule").is_none());
    assert!(lookup_attack("").is_none());
    // Prefix-table lookup removed with forensicnomicon dep.
    assert!(lookup_attack("RAT_QuasarRat").is_none());
    assert!(lookup_attack("Ransomware_LockBit").is_none());
}

// --- RED: these tests define the desired behaviour and fail until the table is embedded ---

#[test]
fn original_20_archetypes_resolve() {
    let cases = [
        ("ransomware_locky", "T1486"),
        ("powershell_", "T1059.001"),
        ("rootkit_", "T1014"),
        ("webshell_", "T1505.003"),
        ("miner_", "T1496"),
        ("wiper_", "T1485"),
        ("stealer_", "T1555"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(
            r.unwrap().technique_id,
            expected_id,
            "wrong technique_id for {prefix:?}"
        );
    }
}

#[test]
fn named_ransomware_families_resolve() {
    let cases = [
        ("lockbit_3_0", "T1486"),
        ("conti_v3", "T1486"),
        ("revil_sample", "T1486"),
        ("blackcat_enc", "T1486"),
        ("alphv_", "T1486"),
        ("cl0p_", "T1486"),
        ("akira_", "T1486"),
        ("blackbasta_", "T1486"),
        ("rhysida_", "T1486"),
        ("play_ransomware", "T1486"),
        ("hive_", "T1486"),
        ("darkside_", "T1486"),
        ("ryuk_", "T1486"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn named_rat_families_resolve() {
    let cases = [
        ("asyncrat_sample", "T1219"),
        ("njrat_", "T1219"),
        ("remcos_", "T1219"),
        ("plugx_", "T1219"),
        ("gh0st_", "T1219"),
        ("xworm_", "T1219"),
        ("quasarrat_", "T1219"),
        ("nanocore_", "T1219"),
        ("darkcomet_", "T1219"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn named_banking_trojan_families_resolve() {
    let cases = [
        ("emotet_epoch5", "T1204"),
        ("trickbot_", "T1204"),
        ("qakbot_", "T1204"),
        ("zeus_panda", "T1204"),
        ("gozi_", "T1204"),
        ("sharkbot_", "T1204"),
        ("godfather_banker", "T1204"),
        ("dridex_", "T1204"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn named_infostealer_families_resolve() {
    let cases = [
        ("redline_stealer", "T1555"),
        ("raccoon_v2", "T1555"),
        ("vidar_sample", "T1555"),
        ("lumma_stealer", "T1555"),
        ("stealc_", "T1555"),
        ("rhadamanthys_", "T1555"),
        ("azorult_", "T1555"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn named_loader_families_resolve() {
    let cases = [
        ("bumblebee_loader", "T1204"),
        ("icedid_", "T1204"),
        ("guloader_", "T1204"),
        ("pikabot_", "T1204"),
        ("darkgate_", "T1204"),
        ("smokeloader_", "T1204"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn credential_attack_prefixes_resolve() {
    let cases = [
        ("kerberoast_ticket", "T1558.003"),
        ("dcsync_dump", "T1003.006"),
        ("lsass_dump", "T1003.001"),
        ("goldenticket_forge", "T1558.001"),
        ("passthehash_", "T1550.002"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn cve_specific_prefixes_resolve() {
    let cases = [
        ("eternalblue_exploit", "T1190"),
        ("log4shell_payload", "T1190"),
        ("proxyshell_", "T1190"),
        ("printnightmare_", "T1068"),
        ("zerologon_", "T1210"),
        ("bluekeep_", "T1210"),
        ("follina_", "T1203"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn c2_framework_prefixes_resolve() {
    let cases = [
        ("cobaltstrike_beacon", "T1071"),
        ("sliver_implant", "T1071"),
        ("havoc_agent", "T1071"),
        ("brute_ratel_", "T1071"),
        ("empire_stager", "T1059.001"),
        ("mimikatz_lsadump", "T1003.001"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn defense_evasion_prefixes_resolve() {
    let cases = [
        ("obfusc_js", "T1027"),
        ("antivm_check", "T1497"),
        ("timestomp_artifact", "T1070.006"),
        ("uacbypass_", "T1548.002"),
        ("dllhijack_", "T1574.001"),
        ("amsi_bypass_", "T1562.001"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn process_injection_prefixes_resolve() {
    let cases = [
        ("prochollow_", "T1055.012"),
        ("reflective_dll", "T1055.001"),
        ("threadhijack_", "T1055.003"),
        ("procdoppel_", "T1055.013"),
        ("apc_inject_", "T1055.004"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn persistence_prefixes_resolve() {
    let cases = [
        ("bootkit_", "T1542.003"),
        ("schtask_persist", "T1053.005"),
        ("regpersist_run", "T1547.001"),
        ("wmi_persist_", "T1546.003"),
        ("com_hijack_", "T1546.015"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn platform_specific_prefixes_resolve() {
    let cases = [
        ("linux_rootkit", "T1014"),
        ("linux_backdoor", "T1543"),
        ("macos_persistence", "T1543"),
        ("android_banker", "T1437"),
        ("ios_spyware", "T1437"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn impact_prefixes_resolve() {
    let cases = [
        ("dos_amplify", "T1499"),
        ("ddos_", "T1499"),
        ("vss_delete", "T1490"),
        ("disk_wipe_mbr", "T1561"),
        ("defacement_", "T1491"),
    ];
    for (prefix, expected_id) in cases {
        let r = lookup_attack(prefix);
        assert!(r.is_some(), "lookup_attack({prefix:?}) returned None — expected Some");
        assert_eq!(r.unwrap().technique_id, expected_id, "wrong id for {prefix:?}");
    }
}

#[test]
fn case_insensitive_lookup() {
    // lookup_attack_for_rule_name in forensicnomicon is case-insensitive;
    // blazehash should lower-case before matching.
    assert!(lookup_attack("RANSOMWARE_LockBit").is_some());
    assert!(lookup_attack("AsyncRat_dropper").is_some());
    assert!(lookup_attack("COBALTSTRIKE_Beacon").is_some());
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
