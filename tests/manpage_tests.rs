/// Tests for `blazehash completions man` — troff man page generation.

#[test]
fn man_page_is_generated() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_blazehash"))
        .args(["completions", "man"])
        .output()
        .expect("failed to run blazehash");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with(".TH") || stdout.contains("BLAZEHASH"),
        "man page output should be troff format, got: {stdout}"
    );
    assert!(
        output.status.success(),
        "blazehash completions man should exit 0"
    );
}
