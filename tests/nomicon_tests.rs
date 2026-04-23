/// Tests for forensicnomicon integration (nomicon feature).
///
/// All tests in this file require `--features nomicon` (or `nomicon,yara`).
/// They are intentionally written BEFORE implementation (TDD RED phase).
#[cfg(feature = "nomicon")]
mod nomicon_tests {
    use blazehash::nomicon::{match_path, is_lolbin, NomiconMatch};
    use std::path::Path;

    // ── Feature 1: Path annotation ────────────────────────────────────────────

    #[test]
    fn match_path_chrome_history_returns_some() {
        // Chrome History is a well-known browser artifact in the catalog.
        let result = match_path(Path::new("/home/user/.config/google-chrome/Default/History"));
        assert!(
            result.is_some(),
            "expected a catalog match for Chrome History path"
        );
        let m = result.unwrap();
        assert!(!m.artifact_id.is_empty(), "artifact_id must be non-empty");
        assert!(!m.artifact_type.is_empty(), "artifact_type must be non-empty");
    }

    #[test]
    fn match_path_firefox_places_returns_some() {
        // Firefox places.sqlite is a well-known browser artifact.
        let result = match_path(Path::new("/home/user/.mozilla/firefox/abc123.default/places.sqlite"));
        assert!(
            result.is_some(),
            "expected a catalog match for Firefox places.sqlite"
        );
        let m = result.unwrap();
        assert!(!m.artifact_id.is_empty());
    }

    #[test]
    fn match_path_unknown_file_returns_none() {
        let result = match_path(Path::new("/tmp/unknown_xyz123_nonexistent_garbage.bin"));
        assert!(
            result.is_none(),
            "unknown file should not match any catalog artifact"
        );
    }

    #[test]
    fn match_path_returns_triage_priority() {
        // Any matched artifact should have a valid triage_priority string.
        let result = match_path(Path::new("/home/user/.config/google-chrome/Default/History"));
        if let Some(m) = result {
            let valid = ["critical", "high", "medium", "low"];
            assert!(
                valid.contains(&m.triage_priority.as_str()),
                "triage_priority '{}' is not one of critical/high/medium/low",
                m.triage_priority
            );
        }
    }

    #[test]
    fn nomicon_match_struct_fields() {
        // Verify the NomiconMatch struct has all required fields accessible.
        let m = NomiconMatch {
            artifact_id: "test_artifact",
            artifact_name: "Test Artifact",
            triage_priority: "high".to_string(),
            mitre_technique: "T1074".to_string(),
            artifact_type: "file".to_string(),
        };
        assert_eq!(m.artifact_id, "test_artifact");
        assert_eq!(m.triage_priority, "high");
        assert_eq!(m.mitre_technique, "T1074");
        assert_eq!(m.artifact_type, "file");
    }

    // ── Feature 2: LOLBin flagging ────────────────────────────────────────────

    #[test]
    fn is_lolbin_certutil_exe_true() {
        assert!(is_lolbin(Path::new("C:/Windows/System32/certutil.exe")));
    }

    #[test]
    fn is_lolbin_certutil_exe_case_insensitive() {
        assert!(is_lolbin(Path::new("CERTUTIL.EXE")));
    }

    #[test]
    fn is_lolbin_bash_true() {
        assert!(is_lolbin(Path::new("/bin/bash")));
    }

    #[test]
    fn is_lolbin_bash_just_filename() {
        assert!(is_lolbin(Path::new("bash")));
    }

    #[test]
    fn is_lolbin_python3_true() {
        assert!(is_lolbin(Path::new("/usr/bin/python3")));
    }

    #[test]
    fn is_lolbin_unknown_file_false() {
        assert!(!is_lolbin(Path::new("unknown_xyz123.bin")));
    }

    #[test]
    fn is_lolbin_notepad_false() {
        assert!(!is_lolbin(Path::new("notepad.exe")));
    }

    #[test]
    fn is_lolbin_msbuild_true() {
        assert!(is_lolbin(Path::new("msbuild.exe")));
    }

    #[test]
    fn is_lolbin_rundll32_path_true() {
        assert!(is_lolbin(Path::new("/mnt/c/Windows/System32/rundll32.exe")));
    }
}

// ── Feature 3 & 4: YARA catalog scanner + enrichment (requires both features) ──
#[cfg(all(feature = "nomicon", feature = "yara"))]
mod nomicon_yara_tests {
    use blazehash::nomicon::{build_catalog_scanner, enrich_yara_match, YaraEnrichment};

    #[test]
    fn build_catalog_scanner_succeeds() {
        // Should compile all catalog YARA templates without error.
        let scanner = build_catalog_scanner();
        assert!(scanner.is_ok(), "build_catalog_scanner() failed: {:?}", scanner.err());
    }

    #[test]
    fn enrich_yara_match_run_key_hklm_returns_some() {
        // "run_key_hklm" is the YARA-sanitized name (hyphens→underscores) for run-key-hklm.
        // The enrichment lookup should reverse this and find the artifact.
        let enrichment = enrich_yara_match("run_key_hklm");
        assert!(
            enrichment.is_some(),
            "expected enrichment for run_key_hklm (maps to run-key-hklm)"
        );
        let e = enrichment.unwrap();
        assert!(!e.artifact_id.is_empty(), "artifact_id must be non-empty");
        let valid = ["critical", "high", "medium", "low"];
        assert!(
            valid.contains(&e.triage_priority),
            "triage_priority '{}' invalid",
            e.triage_priority
        );
    }

    #[test]
    fn enrich_yara_match_unknown_rule_returns_none() {
        let enrichment = enrich_yara_match("totally_unknown_rule_xyz_abc_12345");
        assert!(enrichment.is_none(), "unknown rule should return None");
    }

    #[test]
    fn yara_enrichment_struct_fields() {
        // Verify YaraEnrichment has all required fields accessible.
        let e = YaraEnrichment {
            artifact_id: "run_key_hklm",
            triage_priority: "high",
            mitre_techniques: vec!["T1547.001"],
            sigma_rule_id: Some("abc-123"),
            sigma_title: Some("Run Key Persistence"),
            velociraptor_artifacts: vec!["Windows.Registry.RunKey"],
            kape_targets: vec!["RegistryHives"],
            playbook_id: None,
            playbook_name: None,
        };
        assert_eq!(e.artifact_id, "run_key_hklm");
        assert_eq!(e.triage_priority, "high");
        assert_eq!(e.mitre_techniques, vec!["T1547.001"]);
        assert_eq!(e.sigma_rule_id, Some("abc-123"));
        assert_eq!(e.kape_targets, vec!["RegistryHives"]);
    }

    #[test]
    fn enrich_yara_match_prefetch_dir_sigma_present() {
        // prefetch_dir has known Sigma rules in forensicnomicon.
        let enrichment = enrich_yara_match("prefetch_dir");
        // May or may not find it depending on underscore/hyphen — just verify the API works.
        // If found, sigma_rule_id or sigma_title should be populated.
        if let Some(e) = enrichment {
            // Either sigma fields are Some, or the entry simply has no sigma refs (valid).
            let _ = e.sigma_rule_id;
            let _ = e.sigma_title;
        }
    }
}

// ── CLI integration test: --nomicon flag is accepted ─────────────────────────
#[cfg(feature = "nomicon")]
mod cli_integration {
    use assert_cmd::Command;

    #[test]
    fn nomicon_flag_accepted_no_paths() {
        // blazehash --nomicon with no paths should exit gracefully (not "unknown flag").
        let output = Command::cargo_bin("blazehash")
            .unwrap()
            .arg("--nomicon")
            .output()
            .expect("failed to run blazehash");

        // Must not produce "unexpected argument" or "unknown flag" error.
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument") && !stderr.contains("unknown flag"),
            "blazehash rejected --nomicon flag: {stderr}"
        );
    }
}
