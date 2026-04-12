use anyhow::{bail, Result};
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::io;

pub fn run(shell_name: &str) -> Result<()> {
    let shell = match shell_name.to_lowercase().as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "powershell" | "pwsh" => Shell::PowerShell,
        other => bail!("unsupported shell: {other}. Supported: bash, zsh, fish, powershell"),
    };
    let mut cmd = crate::cli::Cli::command();
    generate(shell, &mut cmd, "blazehash", &mut io::stdout());
    Ok(())
}
