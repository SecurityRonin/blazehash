use blazehash::attack::lookup_attack;

#[test]
fn test_unknown_rule_returns_none() {
    assert!(lookup_attack("SomeRandomRule").is_none());
    assert!(lookup_attack("").is_none());
    // Known rules now resolve via the embedded prefix table:
    assert!(lookup_attack("RAT_QuasarRat").is_some());
    assert!(lookup_attack("Ransomware_LockBit").is_some());
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
        ("stealer_", "T1041"),  // generic stealer_ → Exfiltration Over C2 Channel
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
        ("lockbit_3_0",        "T1486"),
        ("conti_v3",           "T1486"),
        ("revil_sample",       "T1486"),
        ("blackcat_enc",       "T1486"),
        ("alphv_",             "T1486"),
        ("cl0p_",              "T1486"),
        ("akira_",             "T1486"),
        ("blackbasta_",        "T1486"),
        ("rhysida_",           "T1486"),
        ("play_ransom_sample", "T1486"),  // play_ransom_ prefix
        ("hive_ransom_v3",     "T1486"),  // hive_ransom_ prefix
        ("darkside_",          "T1486"),
        ("ryuk_",              "T1486"),
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
        ("quasar_rat_v2", "T1219"),   // quasar_ prefix (table uses quasar_ not quasarrat_)
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
        ("emotet_epoch5",    "T1566"),  // emotet_ → Phishing
        ("trickbot_",        "T1185"),  // trickbot_ → Browser Session Hijacking
        ("qakbot_",          "T1185"),
        ("zeus_panda",       "T1185"),  // zeus_ → Browser Session Hijacking
        ("gozi_",            "T1185"),
        ("sharkbot_",        "T1185"),
        ("godfather_banker", "T1185"),  // godfather_ → Browser Session Hijacking
        ("dridex_",          "T1185"),
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
        ("redline_stealer", "T1552"),  // T1552 Unsecured Credentials
        ("raccoon_v2",      "T1552"),
        ("vidar_sample",    "T1552"),
        ("lumma_stealer",   "T1552"),
        ("stealc_",         "T1552"),
        ("rhadamanthys_",   "T1552"),
        ("azorult_",        "T1552"),
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
        ("bumblebee_loader", "T1105"),  // T1105 Ingress Tool Transfer
        ("icedid_",          "T1105"),
        ("guloader_",        "T1105"),
        ("pikabot_",         "T1105"),
        ("darkgate_",        "T1105"),
        ("smokeloader_",     "T1105"),
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
        ("eternalblue_exploit", "T1210"),  // T1210 Exploitation of Remote Services
        ("log4shell_payload",   "T1190"),  // T1190 Exploit Public-Facing Application
        ("proxyshell_",         "T1190"),
        ("printnightmare_",     "T1068"),  // T1068 Exploitation for Privilege Escalation
        ("zerologon_",          "T1068"),  // zerologon is privilege escalation, not remote services
        ("bluekeep_",           "T1210"),  // T1210 Exploitation of Remote Services
        ("follina_",            "T1203"),  // T1203 Exploitation for Client Execution
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
        ("cobaltstrike_beacon", "T1219"),    // T1219 Remote Access Software
        ("sliver_implant",      "T1219"),
        ("havoc_agent",         "T1219"),
        ("brute_ratel_",        "T1219"),
        ("empire_stager",       "T1059.001"),
        ("mimikatz_lsadump",    "T1003"),    // mimikatz_ → T1003 OS Credential Dumping
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
        ("linux_rootkit_x",    "T1014"),  // linux_rootkit_ prefix
        ("linux_backdoor_ssh", "T1505"),  // linux_backdoor_ → Server Software Component
        ("macos_persist_plist","T1547"),  // macos_persist_ → Boot or Logon Autostart Execution
        ("android_banker_x",   "T1185"),  // android_banker_ → Browser Session Hijacking
        ("ios_spyware_x",      "T1430"),  // ios_spyware_ → Location Tracking
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
        ("dos_amplify", "T1499"),   // dos_ → Endpoint Denial of Service
        ("ddos_amp",   "T1498"),   // ddos_ → Network Denial of Service (not T1499)
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

// ── Pruning RED tests ───────────────────────────────────────────────────────
// Assert entries that should be removed/renamed. All fail until table updated.

#[test]
fn golang_prefix_replaces_go() {
    assert!(
        lookup_attack("golang_implant").is_some(),
        "golang_implant should match golang_ prefix"
    );
    assert!(
        lookup_attack("go_rat").is_none(),
        "go_rat should not match after go_ is removed"
    );
}

#[test]
fn pruned_language_prefixes_return_none() {
    for rule in &["perl_backdoor", "ruby_rat", "java_trojan", "nodejs_stealer"] {
        assert!(
            lookup_attack(rule).is_none(),
            "'{rule}' should return None after language pruning"
        );
    }
}

#[test]
fn pruned_generic_recon_prefixes_return_none() {
    for rule in &[
        "scan_tool",
        "recon_kit",
        "enum_users",
        "discovery_module",
        "harvest_creds",
        "osint_framework",
    ] {
        assert!(
            lookup_attack(rule).is_none(),
            "'{rule}' should return None after recon pruning"
        );
    }
}

#[test]
fn pruned_windows_registry_prefixes_return_none() {
    for rule in &["reg_editor", "event_log_cleaner", "prefetch_wipe"] {
        assert!(
            lookup_attack(rule).is_none(),
            "'{rule}' should return None after registry pruning"
        );
    }
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
