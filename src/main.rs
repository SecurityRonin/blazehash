mod cli;
mod commands;
mod handlers;
mod mcp;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Mode};
use commands::merge::MergeArgs;
use commands::update::UpdateArgs;
use commands::vt::VtArgs;
use commands::watch::WatchArgs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Elevated MFT worker subprocess: enumerate $MFT, write TSV results, exit.
    // This path is taken when the process was spawned by spawn_elevated_mft_worker().
    #[cfg(target_os = "windows")]
    if let Some(ref output_file) = cli.mft_worker_output {
        let root = cli
            .paths
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."));
        blazehash::walk_windows_mft::run_mft_worker(&root, cli.recursive, output_file)?;
        return Ok(());
    }

    if let Mode::Mcp = cli.mode() {
        mcp::run();
        return Ok(());
    }

    if let Mode::Bench = cli.mode() {
        commands::bench::run(cli.gpu, cli.no_calibrate)?;
        return Ok(());
    }

    if let Mode::Diff = cli.mode() {
        let has_diff = commands::diff::run(
            &cli.paths,
            cli.recursive,
            &cli.compare_by,
            cli.show_identical,
        )?;
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

    // Unconditional bloom-file guard — runs even without the nsrl feature.
    // Bloom filters are probabilistic (false positives) and must never be used
    // for known-good filtering in a forensic context.
    if let Some(ref nsrl_path) = cli.nsrl {
        let ext = nsrl_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "bloom" {
            anyhow::bail!(
                "bloom filter files are not supported for --nsrl. \
                 Bloom filters are probabilistic and can produce false positives, \
                 potentially suppressing evidence. Use a SQLite database (--nsrl file.db) instead."
            );
        }
    }

    let algorithms = cli.flat_algorithms();
    let output = cli.resolve_output();

    // NsrlBuildBloom needs output before the main match
    if let Mode::NsrlBuildBloom = cli.mode() {
        #[cfg(feature = "nsrl")]
        {
            let db = cli.paths.get(2).ok_or_else(|| {
                anyhow::anyhow!("usage: blazehash nsrl build-bloom <input.db> --output <out.bloom>")
            })?;
            let out = output
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--output required for nsrl build-bloom"))?;
            blazehash::nsrl::build_bloom(db, out, 0.001)?;
            eprintln!("[+] Bloom filter written to {}", out.display());
            return Ok(());
        }
        #[cfg(not(feature = "nsrl"))]
        anyhow::bail!("NSRL support requires the `nsrl` feature: cargo build --features nsrl");
    }

    if let Mode::Merge = cli.mode() {
        let inputs: Vec<PathBuf> = cli.paths[1..].to_vec();
        let out = output.ok_or_else(|| anyhow::anyhow!("merge requires -o <output>"))?;
        commands::merge::run_merge(MergeArgs { inputs, output: out })?;
        return Ok(());
    }

    if let Mode::Update = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash update <manifest> <path>"))?;
        let path = cli
            .paths
            .get(2)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash update <manifest> <path>"))?;
        let out = output.unwrap_or_else(|| manifest.clone());
        commands::update::run_update(UpdateArgs {
            manifest,
            path,
            algos: algorithms,
            output: out,
        })?;
        return Ok(());
    }

    if let Mode::Watch = cli.mode() {
        let watch_path = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash watch <path> -k <manifest>"))?;
        let manifest = cli
            .known
            .first()
            .cloned()
            .or_else(|| {
                blazehash::manifest_loader::find_manifest(&[watch_path.as_path()]).ok()
            })
            .ok_or_else(|| {
                anyhow::anyhow!("usage: blazehash watch <path> -k <manifest>")
            })?;
        commands::watch::run_watch(WatchArgs {
            path: watch_path,
            manifest,
            algos: algorithms,
        })?;
        return Ok(());
    }

    if let Mode::Vt = cli.mode() {
        let manifest = cli
            .paths
            .into_iter()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("vt requires a manifest path"))?;
        let api_key = cli
            .api_key
            .clone()
            .or_else(|| std::env::var("VT_API_KEY").ok())
            .ok_or_else(|| {
                anyhow::anyhow!("VT API key required (--api-key or VT_API_KEY env var)")
            })?;
        commands::vt::run_vt(VtArgs { manifest, api_key })?;
        return Ok(());
    }

    match cli.mode() {
        Mode::Mcp => unreachable!(),
        Mode::Bench => unreachable!(),
        Mode::Diff => unreachable!(),
        Mode::Dedup => unreachable!(),
        Mode::NsrlBuildBloom => unreachable!(),
        Mode::Merge => unreachable!(),
        Mode::Update => unreachable!(),
        Mode::Vt => unreachable!(),
        Mode::Watch => unreachable!(),
        Mode::Sign => {
            let manifest = cli
                .paths
                .get(1)
                .map(PathBuf::from)
                .or_else(|| {
                    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                    blazehash::manifest_loader::find_manifest(&[cwd.as_path()]).ok()
                })
                .ok_or_else(|| anyhow::anyhow!("usage: blazehash sign [manifest]"))?;
            blazehash::signing::sign(&manifest)?;
        }
        Mode::VerifySig => {
            let manifest = PathBuf::from(cli.paths.get(1).ok_or_else(|| {
                anyhow::anyhow!("usage: blazehash verify-sig <manifest> --expected-pubkey <hex>")
            })?);
            let pubkey = cli.expected_pubkey.as_deref().unwrap_or("");
            let valid = blazehash::signing::verify_sig(&manifest, pubkey)?;
            if !valid {
                std::process::exit(1);
            }
        }
        Mode::SizeOnly => {
            commands::size_only::run(&cli.paths, cli.recursive, output.as_ref(), cli.mft)?;
        }
        Mode::Audit => {
            commands::audit::run(
                &cli.paths,
                &cli.known,
                cli.recursive,
                output.as_ref(),
                cli.fuzzy_threshold,
                cli.fuzzy_top,
                cli.ignore_sig,
                cli.expected_pubkey.clone(),
            )?;
        }
        Mode::VerifyImage => {
            commands::verify_image::run(&cli.paths, output.as_ref())?;
        }
        Mode::Piecewise => {
            let chunk_str = cli.piecewise.as_ref().unwrap();
            commands::piecewise::run(
                &cli.paths,
                &algorithms,
                chunk_str,
                cli.bare,
                output.as_ref(),
            )?;
        }
        Mode::Stdin => {
            commands::stdin::run(&algorithms, &cli.format, cli.bare, output.as_ref())?;
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
                output: output.as_ref(),
                no_cache: cli.no_cache,
                no_gpu: cli.no_gpu,
                filter: &filter,
                nsrl: cli.nsrl.as_ref(),
                nsrl_exclude: cli.nsrl_exclude,
                #[cfg(feature = "nsrl")]
                nsrl_hsh: cli.nsrl_hsh.as_ref(),
                sign: cli.sign,
                ads: cli.ads,
                entropy: cli.entropy,
            })?;
        }
    }

    Ok(())
}
