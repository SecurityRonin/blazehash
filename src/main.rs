mod cli;
mod commands;
mod handlers;
mod mcp;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Mode};
use std::path::PathBuf;

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

    if let Mode::Diff = cli.mode() {
        let has_diff = commands::diff::run(&cli.paths)?;
        if has_diff {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Mode::Dedup = cli.mode() {
        let algorithms = cli.flat_algorithms();
        let has_dupes = commands::dedup::run(
            &cli.paths,
            &algorithms,
            cli.recursive,
            cli.dedup_unique,
            cli.dedup_dupes,
        )?;
        if has_dupes {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Mode::NsrlBuildBloom = cli.mode() {
        #[cfg(feature = "nsrl")]
        {
            let db = cli.paths.get(2).ok_or_else(|| {
                anyhow::anyhow!(
                    "usage: blazehash nsrl build-bloom <input.db> --output <out.bloom>"
                )
            })?;
            let out = cli.output.as_ref().ok_or_else(|| {
                anyhow::anyhow!("--output required for nsrl build-bloom")
            })?;
            blazehash::nsrl::build_bloom(db, out, 0.001)?;
            eprintln!("[+] Bloom filter written to {}", out.display());
        }
        #[cfg(not(feature = "nsrl"))]
        {
            anyhow::bail!(
                "NSRL support requires the `nsrl` feature: cargo build --features nsrl"
            );
        }
        return Ok(());
    }

    let algorithms = cli.flat_algorithms();

    match cli.mode() {
        Mode::Mcp => unreachable!(),
        Mode::Bench => unreachable!(),
        Mode::Diff => unreachable!(),
        Mode::Dedup => unreachable!(),
        Mode::NsrlBuildBloom => unreachable!(),
        Mode::Sign => {
            let manifest = cli.paths.get(1)
                .map(|p| PathBuf::from(p))
                .or_else(|| {
                    {
                        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                        blazehash::manifest_loader::find_manifest(&[cwd.as_path()]).ok()
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("usage: blazehash sign [manifest]"))?;
            blazehash::signing::sign(&manifest)?;
        }
        Mode::VerifySig => {
            let manifest = PathBuf::from(cli.paths.get(1)
                .ok_or_else(|| anyhow::anyhow!("usage: blazehash verify-sig <manifest> --expected-pubkey <hex>"))?);
            let pubkey = cli.expected_pubkey.as_deref().unwrap_or("");
            let valid = blazehash::signing::verify_sig(&manifest, pubkey)?;
            if !valid { std::process::exit(1); }
        }
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
                cli.ignore_sig,
                cli.expected_pubkey.clone(),
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
        Mode::Stdin => {
            commands::stdin::run(&algorithms, &cli.format, cli.bare, cli.output.as_ref())?;
        }
        Mode::Hash => {
            let filter = cli.build_walk_filter()?;
            commands::hash::run(commands::hash::HashOptions {
                paths: &cli.paths,
                algorithms: &algorithms,
                recursive: cli.recursive,
                format: &cli.format,
                bare: cli.bare,
                resume: cli.resume,
                output: cli.output.as_ref(),
                no_cache: cli.no_cache,
                no_gpu: cli.no_gpu,
                filter: &filter,
                nsrl: cli.nsrl.as_ref(),
                nsrl_exclude: cli.nsrl_exclude,
                sign: cli.sign,
            })?;
        }
    }

    Ok(())
}
