mod cli;
mod commands;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Mode};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let algorithms = cli.flat_algorithms();

    match cli.mode() {
        Mode::SizeOnly => {
            commands::size_only::run(&cli.paths, cli.recursive, cli.output.as_ref())?;
        }
        Mode::Audit => {
            commands::audit::run(&cli.paths, &cli.known, cli.recursive, cli.output.as_ref())?;
        }
        Mode::Piecewise => {
            let chunk_str = cli.piecewise.as_ref().unwrap();
            commands::piecewise::run(
                &cli.paths,
                &algorithms,
                chunk_str,
                cli.bare,
                cli.output.as_ref(),
            )?;
        }
        Mode::Hash => {
            commands::hash::run(
                &cli.paths,
                &algorithms,
                cli.recursive,
                &cli.format,
                cli.bare,
                cli.resume,
                cli.output.as_ref(),
            )?;
        }
    }

    Ok(())
}
