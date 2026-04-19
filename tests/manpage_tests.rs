/// Tests for `blazehash completions man` — troff man page generation.

#[test]
fn man_page_is_generated() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_blazehash"))
        .args(["completions", "man"])
        .output()
        .expect("failed to run blazehash");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // clap_mangen emits troff macros: may start with .ie/.el prelude or .TH directly.
    // The output must contain the .TH macro and the binary name.
    assert!(
        stdout.contains(".TH") && stdout.contains("blazehash"),
        "man page output should be troff format containing .TH, got: {stdout}"
    );
    assert!(
        output.status.success(),
        "blazehash completions man should exit 0"
    );
}
