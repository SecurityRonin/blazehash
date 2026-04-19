use anyhow::{bail, Result};
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use std::io;

pub fn run(shell_name: &str) -> Result<()> {
    if shell_name.eq_ignore_ascii_case("man") {
        let cmd = crate::cli::Cli::command();
        let man = clap_mangen::Man::new(cmd);
        man.render(&mut io::stdout())?;
        return Ok(());
    }
    let shell = match shell_name.to_lowercase().as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "powershell" | "pwsh" => Shell::PowerShell,
        other => bail!(
            "unsupported shell: {other}. Supported: bash, zsh, fish, powershell, man"
        ),
    };
    let mut cmd = crate::cli::Cli::command();
    generate(shell, &mut cmd, "blazehash", &mut io::stdout());
    Ok(())
}
