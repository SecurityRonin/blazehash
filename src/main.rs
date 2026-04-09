mod cli;
mod commands;
mod handlers;
mod mcp;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Mode};

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Mode::Mcp = cli.mode() {
        mcp::run();
        return Ok(());
    }

    if let Mode::Bench = cli.mode() {
        commands::bench::run(cli.gpu, cli.no_calibrate)?;
        return Ok(());
    }

    let algorithms = cli.flat_algorithms();

    match cli.mode() {
        Mode::Mcp => unreachable!(),
        Mode::Bench => unreachable!(),
        Mode::SizeOnly => {
            commands::size_only::run(&cli.paths, cli.recursive, cli.output.as_ref())?;
        }
        Mode::Audit => {
            commands::audit::run(
                &cli.paths,
                &cli.known,
                cli.recursive,
                cli.output.as_ref(),
                cli.fuzzy_threshold,
                cli.fuzzy_top,
            )?;
        }
        Mode::VerifyImage => {
            commands::verify_image::run(&cli.paths, cli.output.as_ref())?;
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
                cli.no_cache,
                cli.no_gpu,
            )?;
        }
    }

    Ok(())
}
