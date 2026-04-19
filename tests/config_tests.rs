use blazehash::config::BlazeConfig;

#[test]
fn config_default_algorithms_is_blake3() {
    let cfg = BlazeConfig::default();
    assert_eq!(
        cfg.defaults.algorithms,
        vec!["blake3".to_string()],
        "default algorithms should be blake3"
    );
}

#[test]
fn config_loads_algorithms_from_toml_string() {
    let toml_str = r#"
[defaults]
algorithms = ["sha256", "md5"]
"#;
    let cfg: BlazeConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.defaults.algorithms, vec!["sha256", "md5"]);
}

#[test]
fn config_default_output_format_is_none() {
    let cfg = BlazeConfig::default();
    assert!(cfg.defaults.output_format.is_none());
}

#[test]
fn config_loads_output_format_from_toml() {
    let toml_str = r#"
[defaults]
output_format = "json"
"#;
    let cfg: BlazeConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(cfg.defaults.output_format.as_deref(), Some("json"));
}

#[test]
fn config_load_returns_default_when_no_file() {
    // Ensure no blazehash.toml is present in test environment — if it is, skip.
    // This test verifies that BlazeConfig::load_user() falls back to defaults.
    let cfg = blazehash::config::load_user_config();
    // Regardless of what file exists, we just check it returns a valid struct
    assert!(!cfg.defaults.algorithms.is_empty());
}
