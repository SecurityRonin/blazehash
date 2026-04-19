mod cli;
mod commands;
mod handlers;
mod mcp;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Mode};
use commands::merge::MergeArgs;
#[cfg(feature = "report")]
use commands::report::ReportArgs;
use commands::update::UpdateArgs;
use commands::vt::VtArgs;
use commands::watch::WatchArgs;
use std::path::PathBuf;

fn parse_manifest_entries(path: &std::path::Path) -> anyhow::Result<Vec<(String, String, String)>> {
    let content = std::fs::read_to_string(path)?;
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Format: "<algo>  <hash>  <path>"
        let parts: Vec<&str> = line.splitn(3, "  ").collect();
        if parts.len() == 3 {
            entries.push((
                parts[0].trim().to_string(),
                parts[2].trim().to_string(),
                parts[1].trim().to_string(),
            ));
        } else {
            eprintln!("warning: skipping unparseable manifest line: {line}");
        }
    }
    Ok(entries)
}

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
            cli.patch,
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
        #[cfg(feature = "hashdb")]
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
        #[cfg(not(feature = "hashdb"))]
        anyhow::bail!("NSRL support requires the `hashdb` feature: cargo build --features hashdb");
    }

    if let Mode::PqSign = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash pq-sign <manifest>"))?;
        let password = std::env::var("BLAZEHASH_SIGN_PASSWORD").unwrap_or_default();
        if password.is_empty() {
            anyhow::bail!(
                "pq-sign requires a password; set the BLAZEHASH_SIGN_PASSWORD environment variable"
            );
        }
        blazehash::pq_signing::pq_sign_with_password(&manifest, &password)?;
        return Ok(());
    }

    if let Mode::PqVerifySig = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash pq-verify-sig <manifest>"))?;
        let pubkey = cli.expected_pubkey.as_deref().unwrap_or("");
        let ok = blazehash::pq_signing::pq_verify_sig(&manifest, pubkey)?;
        if !ok {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Mode::Cosign = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash cosign <manifest>"))?;
        blazehash::cosign::cosign(&manifest)?;
        return Ok(());
    }

    if let Mode::VerifyMsig = cli.mode() {
        let manifest = cli.paths.get(1).cloned().ok_or_else(|| {
            anyhow::anyhow!("usage: blazehash verify-msig <manifest> --threshold N")
        })?;
        let valid = blazehash::cosign::verify_msig(&manifest, cli.threshold)?;
        if !valid {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Mode::Merge = cli.mode() {
        let inputs: Vec<PathBuf> = cli.paths[1..].to_vec();
        let out = output.ok_or_else(|| anyhow::anyhow!("merge requires -o <output>"))?;
        commands::merge::run_merge(MergeArgs {
            inputs,
            output: out,
        })?;
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
            .or_else(|| blazehash::manifest_loader::find_manifest(&[watch_path.as_path()]).ok())
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash watch <path> -k <manifest>"))?;
        commands::watch::run_watch(WatchArgs {
            path: watch_path,
            manifest,
            algos: algorithms,
        })?;
        return Ok(());
    }

    #[cfg(feature = "report")]
    if let Mode::Report = cli.mode() {
        let manifest = cli.paths.get(1).cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "usage: blazehash report <manifest> --examiner <name> --case <id> -o <out.html>"
            )
        })?;
        let out = output.ok_or_else(|| anyhow::anyhow!("report requires -o <output.html>"))?;
        let examiner = cli
            .examiner
            .clone()
            .ok_or_else(|| anyhow::anyhow!("report requires --examiner <name>"))?;
        let case_id = cli
            .case_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("report requires --case <id>"))?;
        commands::report::run_report(ReportArgs {
            manifest,
            output: out,
            examiner,
            case_id,
        })?;
        return Ok(());
    }

    if let Mode::Completions = cli.mode() {
        let shell = cli.paths.get(1).and_then(|p| p.to_str()).ok_or_else(|| {
            anyhow::anyhow!("usage: blazehash completions <bash|zsh|fish|powershell>")
        })?;
        commands::completions::run(shell)?;
        return Ok(());
    }

    if let Mode::Selfcheck = cli.mode() {
        let result = commands::selfcheck::selfcheck()?;
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            commands::selfcheck::print_selfcheck(&result);
        }
        return Ok(());
    }

    #[cfg(feature = "qr")]
    if let Mode::Qr = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash qr <manifest> -o <label.png>"))?;
        match output {
            Some(out) => {
                blazehash::qr_label::generate_qr_png(&manifest, &out, None)?;
                eprintln!("[+] QR label: {}", out.display());
            }
            None => {
                let text = blazehash::qr_label::generate_qr_text(&manifest, None)?;
                println!("{text}");
            }
        }
        return Ok(());
    }

    #[cfg(feature = "tui")]
    if let Mode::Tui = cli.mode() {
        let algorithms = cli.flat_algorithms();
        let filter = cli.build_walk_filter()?;
        blazehash::tui::run_tui(
            &cli.paths[1..],
            &algorithms,
            cli.recursive,
            &filter,
            cli.entropy,
        )?;
        return Ok(());
    }

    #[cfg(feature = "ots")]
    if let Mode::OtsStamp = cli.mode() {
        let manifest = cli
            .paths
            .get(2)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash ots stamp <manifest>"))?;
        blazehash::ots::stamp(&manifest)?;
        return Ok(());
    }

    #[cfg(feature = "ots")]
    if let Mode::OtsVerify = cli.mode() {
        let manifest = cli
            .paths
            .get(2)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash ots verify <manifest>"))?;
        let valid = blazehash::ots::verify(&manifest)?;
        if !valid {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Mode::Merkle = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash merkle <manifest>"))?;
        let records = blazehash::manifest_loader::load_manifest(&manifest)?;
        let entries: Vec<(String, String, String)> = records
            .iter()
            .filter_map(|r| {
                let sha256 = r
                    .hashes
                    .get(&blazehash::algorithm::Algorithm::Sha256)
                    .cloned()?;
                let path = r.path.to_string_lossy().into_owned();
                Some(("sha256".to_string(), path, sha256))
            })
            .collect();
        let root = blazehash::merkle::merkle_root(&entries)?;
        println!("{root}");
        return Ok(());
    }

    if let Mode::MerkleProof = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash merkle-proof <manifest> --path <p>"))?;
        let file_path = cli
            .merkle_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("merkle-proof requires --path <file_path>"))?;
        let records = blazehash::manifest_loader::load_manifest(&manifest)?;
        let entries: Vec<(String, String, String)> = records
            .iter()
            .filter_map(|r| {
                let sha256 = r
                    .hashes
                    .get(&blazehash::algorithm::Algorithm::Sha256)
                    .cloned()?;
                let path = r.path.to_string_lossy().into_owned();
                Some(("sha256".to_string(), path, sha256))
            })
            .collect();
        let proof = blazehash::merkle::generate_proof(&entries, file_path)?;
        println!("{}", serde_json::to_string(&proof)?);
        return Ok(());
    }

    if let Mode::MerkleVerify = cli.mode() {
        let root = cli
            .merkle_root
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("merkle-verify requires --root <hex>"))?;
        let file_path = cli
            .merkle_path
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("merkle-verify requires --path <path>"))?;
        let sha256_hex = cli
            .merkle_sha256
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("merkle-verify requires --sha256 <hex>"))?;
        let proof_json = cli
            .merkle_proof
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("merkle-verify requires --proof <json>"))?;
        let proof: Vec<String> = serde_json::from_str(proof_json)
            .map_err(|e| anyhow::anyhow!("invalid proof JSON: {e}"))?;
        let ok = blazehash::merkle::verify_proof(root, file_path, sha256_hex, &proof)?;
        if !ok {
            eprintln!("proof verification FAILED");
            std::process::exit(1);
        }
        println!("ok");
        return Ok(());
    }

    if let Mode::Disclose = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash disclose <manifest> --paths <p1,p2> [-o proof.json]"))?;
        let paths_str = cli
            .disclose_paths
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("disclose requires --paths <comma-separated-paths>"))?;
        let disclosed_paths: Vec<&str> = paths_str.split(',').map(str::trim).collect();
        let entries = parse_manifest_entries(&manifest)?;
        let proof = blazehash::disclosure::generate_selective_proof(&entries, &disclosed_paths)?;
        let json = serde_json::to_string_pretty(&proof)?;
        match output {
            Some(ref out) => std::fs::write(out, &json)?,
            None => println!("{json}"),
        }
        return Ok(());
    }

    if let Mode::ProveMembership = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash prove-membership <manifest> --sha256 <hex> [-o proof.json]"))?;
        let sha256_hex = cli
            .merkle_sha256
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("prove-membership requires --sha256 <hex>"))?;
        let entries = parse_manifest_entries(&manifest)?;
        let proof = blazehash::disclosure::prove_hash_membership(&entries, sha256_hex)?;
        let json = serde_json::to_string_pretty(&proof)?;
        match output {
            Some(ref out) => std::fs::write(out, &json)?,
            None => println!("{json}"),
        }
        return Ok(());
    }

    if let Mode::PathOnly = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash path-only <manifest>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::path_only::path_only_manifest(manifest.as_ref(), &mut out)?;
        return Ok(());
    }

    if let Mode::HashOnly = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash hash-only <manifest> [--hash-only-algo ALGO]"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::hash_only::hash_only_manifest(
            manifest.as_ref(),
            cli.hash_only_algo.as_deref(),
            &mut out,
        )?;
        return Ok(());
    }

    if let Mode::Redact = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash redact <manifest> -o <redacted.hash>"))?;
        let out = output
            .ok_or_else(|| anyhow::anyhow!("redact requires -o <output>"))?;
        commands::redact::redact_manifest(&manifest, &out)?;
        return Ok(());
    }

    if let Mode::Annotate = cli.mode() {
        let note = cli.annotate_note.as_deref()
            .ok_or_else(|| anyhow::anyhow!("--note is required for blazehash annotate"))?;
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash annotate <manifest> --note <message>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::annotate::annotate_manifest(manifest.as_ref(), note, &mut out)?;
        return Ok(());
    }

    if let Mode::Shuffle = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash shuffle <manifest>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::shuffle::shuffle_manifest(manifest.as_ref(), cli.shuffle_seed, &mut out)?;
        return Ok(());
    }

    if let Mode::Reverse = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash reverse <manifest>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::reverse::reverse_manifest(manifest.as_ref(), &mut out)?;
        return Ok(());
    }

    if let Mode::UniqueHash = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash unique-hash <manifest>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::unique_hash::unique_hash_manifest(manifest.as_ref(), &mut out)?;
        return Ok(());
    }

    if let Mode::Balance = cli.mode() {
        let parts = cli.balance_parts
            .ok_or_else(|| anyhow::anyhow!("--parts is required for blazehash balance"))?;
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash balance <manifest> --parts <N>"))?;
        let out_dir = cli.output.as_deref();
        let paths = crate::commands::balance::balance_manifest(manifest.as_ref(), parts, out_dir)?;
        for p in paths {
            println!("{}", p.display());
        }
        return Ok(());
    }

    if let Mode::Interleave = cli.mode() {
        let a = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash interleave <manifest-a> <manifest-b>"))?;
        let b = cli.paths.get(2)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash interleave <manifest-a> <manifest-b>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::interleave::interleave_manifests(a.as_ref(), b.as_ref(), &mut out)?;
        return Ok(());
    }

    if let Mode::Sample = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash sample <manifest> [--count N]"))?;
        if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::sample::sample_manifest(&manifest, cli.count, &mut f)?;
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::sample::sample_manifest(&manifest, cli.count, &mut handle)?;
        }
        return Ok(());
    }

    if let Mode::Timeline = cli.mode() {
        let manifest_path = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash timeline <manifest> [-o report.html]"))?;
        if !manifest_path.exists() {
            anyhow::bail!("manifest not found: {}", manifest_path.display());
        }
        let events = blazehash::timeline::build_timeline(&manifest_path)?;
        match &output {
            Some(out) => {
                let content = if out.extension().map(|e| e == "html").unwrap_or(false) {
                    blazehash::timeline::render_timeline_html(&events, &manifest_path)?
                } else {
                    serde_json::to_string_pretty(&events)?
                };
                std::fs::write(out, content)?;
            }
            None => println!("{}", serde_json::to_string_pretty(&events)?),
        }
        return Ok(());
    }

    if let Mode::Stats = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash stats <manifest>"))?;
        commands::stats::run_stats(&manifest, cli.json)?;
        return Ok(());
    }

    if let Mode::Filter = cli.mode() {
        let manifest_path = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash filter <manifest> [--include GLOB]... [--algo ALGO] [-o output]"))?;
        if !manifest_path.exists() {
            anyhow::bail!("manifest not found: {}", manifest_path.display());
        }
        let opts = commands::filter::FilterOpts {
            include: if cli.include.is_empty() { None } else { Some(&cli.include) },
            algo: cli.filter_algo.as_deref(),
        };
        if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::filter::filter_manifest(&manifest_path, &opts, &mut f)?;
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::filter::filter_manifest(&manifest_path, &opts, &mut handle)?;
        }
        return Ok(());
    }

    if let Mode::Exclude = cli.mode() {
        let pattern = cli.exclude_pattern.as_deref()
            .ok_or_else(|| anyhow::anyhow!("--exclude-pattern is required for blazehash exclude"))?;
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash exclude <manifest> --exclude-pattern <GLOB>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::exclude::exclude_manifest(manifest.as_ref(), pattern, &mut out)?;
        return Ok(());
    }

    if let Mode::Normalize = cli.mode() {
        let manifest_path = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash normalize <manifest> [--strip-prefix PREFIX] [--add-prefix PREFIX] [-o output]"))?;
        if !manifest_path.exists() {
            anyhow::bail!("manifest not found: {}", manifest_path.display());
        }
        let opts = commands::normalize::NormalizeOpts {
            strip_prefix: cli.strip_prefix.as_deref(),
            add_prefix: cli.add_prefix.as_deref(),
        };
        if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::normalize::normalize_manifest(&manifest_path, &opts, &mut f)?;
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::normalize::normalize_manifest(&manifest_path, &opts, &mut handle)?;
        }
        return Ok(());
    }

    if let Mode::Archive = cli.mode() {
        let archive_path = std::path::Path::new(
            cli.paths.get(1).map(|s| s.as_os_str()).unwrap_or_default(),
        );
        if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::archive::hash_archive(archive_path, &mut f)?;
        } else {
            let stdout = std::io::stdout();
            commands::archive::hash_archive(archive_path, &mut stdout.lock())?;
        }
        return Ok(());
    }

    if let Mode::Convert = cli.mode() {
        let input = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash convert <file> --from <format> [-o output]"))?;
        let format = cli
            .from_format
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--from <format> is required (sha256sum, md5sum, sha1sum, hashdeep, sfv)"))?;
        if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::convert::convert_manifest(&input, format, &mut f)?;
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::convert::convert_manifest(&input, format, &mut handle)?;
        }
        return Ok(());
    }

    if let Mode::Head = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash head <manifest> [--count N]"))?;
        if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::head::head_manifest(&manifest, cli.count, &mut f)?;
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::head::head_manifest(&manifest, cli.count, &mut handle)?;
        }
        return Ok(());
    }

    if let Mode::Tail = cli.mode() {
        let manifest_path = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("tail: missing manifest path"))?;
        if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::tail::tail_manifest(manifest_path, cli.count, &mut f)?;
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::tail::tail_manifest(manifest_path, cli.count, &mut handle)?;
        }
        return Ok(());
    }

    if let Mode::Search = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash search <manifest> [--search-path QUERY] [--hash PREFIX]"))?;
        let opts = commands::search::SearchOpts {
            path_query: cli.search_path.as_deref(),
            hash_query: cli.search_hash.as_deref(),
            ignore_case: cli.ignore_case,
        };
        let matched = if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::search::search_manifest(&manifest, &opts, &mut f)?
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::search::search_manifest(&manifest, &opts, &mut handle)?
        };
        if matched == 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Mode::Export = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash export <manifest> --format <csv|tsv|jsonl>"))?;
        let fmt = cli
            .export_format
            .as_deref()
            .unwrap_or("csv");
        if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::export::export_manifest(&manifest, fmt, &mut f)?;
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::export::export_manifest(&manifest, fmt, &mut handle)?;
        }
        return Ok(());
    }

    if let Mode::ApplyPatch = cli.mode() {
        let manifest = cli.paths.get(1).cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash apply-patch <manifest> <patch-file>"))?;
        let patch_file = cli.paths.get(2).cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash apply-patch <manifest> <patch-file>"))?;
        if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::apply_patch::apply_patch(&manifest, &patch_file, &mut f)?;
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::apply_patch::apply_patch(&manifest, &patch_file, &mut handle)?;
        }
        return Ok(());
    }

    if let Mode::Subtract = cli.mode() {
        let left = cli.paths.get(1).cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash subtract <manifest_a> <manifest_b>"))?;
        let right = cli.paths.get(2).cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash subtract <manifest_a> <manifest_b>"))?;
        let kept = if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::subtract::subtract_manifests(&left, &right, &mut f)?
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::subtract::subtract_manifests(&left, &right, &mut handle)?
        };
        if kept == 0 { std::process::exit(1); }
        return Ok(());
    }

    if let Mode::SymDiff = cli.mode() {
        let a = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash sym-diff <manifest-a> <manifest-b>"))?;
        let b = cli.paths.get(2)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash sym-diff <manifest-a> <manifest-b>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::sym_diff::sym_diff_manifests(a.as_ref(), b.as_ref(), &mut out)?;
        return Ok(());
    }

    if let Mode::Intersect = cli.mode() {
        let left = cli.paths.get(1).cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash intersect <manifest_a> <manifest_b>"))?;
        let right = cli.paths.get(2).cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash intersect <manifest_a> <manifest_b>"))?;
        let matched = if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::intersect::intersect_manifests(&left, &right, &mut f)?
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::intersect::intersect_manifests(&left, &right, &mut handle)?
        };
        if matched == 0 { std::process::exit(1); }
        return Ok(());
    }

    if let Mode::Sort = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash sort <manifest> [--sort-by path|hash|algo|ext]"))?;
        commands::sort::validate_sort_by(&cli.sort_by)?;
        if let Some(out_path) = &output {
            let mut f = std::fs::File::create(out_path)?;
            commands::sort::sort_manifest(&manifest, &cli.sort_by, &mut f)?;
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            commands::sort::sort_manifest(&manifest, &cli.sort_by, &mut handle)?;
        }
        return Ok(());
    }

    if let Mode::Lint = cli.mode() {
        let manifest = cli
            .paths
            .get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash lint <manifest>"))?;
        let report = commands::lint::lint_manifest(&manifest)?;
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            commands::lint::print_report(&report);
        }
        if !report.ok() {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Mode::Info = cli.mode() {
        let manifest_path = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("info: missing manifest path"))?;
        let stdout = std::io::stdout();
        let mut out: Box<dyn std::io::Write> = match &cli.output {
            Some(p) => Box::new(std::fs::File::create(p)?),
            None => Box::new(stdout.lock()),
        };
        commands::info::run_info(manifest_path, cli.json, &mut out)?;
        return Ok(());
    }

    if let Mode::Missing = cli.mode() {
        let manifest_path = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("missing: missing manifest path"))?;
        let root = cli.merkle_root.as_deref().map(std::path::Path::new);
        let stdout = std::io::stdout();
        let mut out: Box<dyn std::io::Write> = match &cli.output {
            Some(p) => Box::new(std::fs::File::create(p)?),
            None => Box::new(stdout.lock()),
        };
        let n = commands::missing::find_missing(manifest_path, root, &mut out)?;
        if n > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Mode::Tag = cli.mode() {
        let manifest_path = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("tag: missing manifest path"))?;
        let stdout = std::io::stdout();
        let mut out: Box<dyn std::io::Write> = match &cli.output {
            Some(p) => Box::new(std::fs::File::create(p)?),
            None => Box::new(stdout.lock()),
        };
        commands::tag::tag_manifest(manifest_path, &cli.tag_set, &cli.tag_unset, &mut out)?;
        return Ok(());
    }

    if let Mode::Verify = cli.mode() {
        let manifest_path = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("verify: missing manifest path"))?;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let result = commands::verify::verify_manifest(
            manifest_path,
            cli.verify_algo.as_deref(),
            &mut out,
        )?;
        if result.failed > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Mode::Count = cli.mode() {
        let manifest_path = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("count: missing manifest path"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        commands::count::count_entries(manifest_path, &mut out)?;
        return Ok(());
    }

    if let Mode::Cat = cli.mode() {
        let input_paths: Vec<&std::path::Path> = cli.paths[1..].iter()
            .map(|p| p.as_path())
            .collect();
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        commands::cat::cat_manifests(&input_paths, &mut out)?;
        return Ok(());
    }

    if let Mode::Split = cli.mode() {
        let manifest_path = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("split: missing manifest path"))?;
        let out_base = cli.output.as_deref()
            .ok_or_else(|| anyhow::anyhow!("split: -o <base> is required"))?;
        commands::split::split_manifest(manifest_path, cli.split_chunk, out_base)?;
        return Ok(());
    }

    if let Mode::Uniq = cli.mode() {
        let manifest_path = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("uniq: missing manifest path"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        commands::uniq::uniq_manifest(manifest_path, &mut out)?;
        return Ok(());
    }

    if let Mode::Checksum = cli.mode() {
        let manifest_path = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("checksum: missing manifest path"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        commands::checksum::checksum_manifest(manifest_path, cli.json, &mut out)?;
        return Ok(());
    }

    if let Mode::Rename = cli.mode() {
        let from = cli.rename_from.as_deref()
            .ok_or_else(|| anyhow::anyhow!("--rename-from is required for blazehash rename"))?;
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("blazehash rename requires a manifest path"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::rename_cmd::rename_manifest(
            manifest.as_ref(),
            from,
            &cli.rename_to,
            &mut out,
        )?;
        return Ok(());
    }

    if let Mode::Slice = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("blazehash slice requires a manifest path"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::slice_cmd::slice_manifest(
            manifest.as_ref(),
            cli.slice_offset,
            cli.count,
            &mut out,
        )?;
        return Ok(());
    }

    if let Mode::Pivot = cli.mode() {
        let algo = cli.pivot_algo.as_deref()
            .ok_or_else(|| anyhow::anyhow!("--pivot-algo is required for blazehash pivot"))?;
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("blazehash pivot requires a manifest path"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::pivot::pivot_manifest(manifest.as_ref(), algo, &mut out)?;
        return Ok(());
    }

    if let Mode::Stamp = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("blazehash stamp requires a manifest path"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::stamp::stamp_manifest(manifest.as_ref(), &mut out)?;
        return Ok(());
    }

    if let Mode::Grep = cli.mode() {
        let pattern = cli.grep_pattern.as_deref()
            .ok_or_else(|| anyhow::anyhow!("--pattern is required for blazehash grep"))?;
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("blazehash grep requires a manifest path"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::grep_cmd::grep_manifest(
            manifest.as_ref(),
            pattern,
            cli.ignore_case,
            &mut out,
        )?;
        return Ok(());
    }

    if let Mode::Tally = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash tally <manifest> [--tally-by ext|dir|algo]"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::tally::tally_manifest(manifest.as_ref(), &cli.tally_by, &mut out)?;
        return Ok(());
    }

    if let Mode::Contains = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash contains <manifest> <term>"))?;
        let term = cli.paths.get(2).and_then(|p| p.to_str())
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash contains <manifest> <term>"))?;
        let found = crate::commands::contains_cmd::contains_manifest(manifest.as_ref(), term)?;
        if !found {
            println!("NOT FOUND");
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Mode::Duplicates = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash duplicates <manifest>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::duplicates::duplicates_manifest(manifest.as_ref(), &mut out)?;
        return Ok(());
    }

    if let Mode::Repair = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash repair <manifest>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::repair::repair_manifest(manifest.as_ref(), &mut out)?;
        return Ok(());
    }

    if let Mode::First = cli.mode() {
        let manifest = cli.paths.get(1)
            .ok_or_else(|| anyhow::anyhow!("usage: blazehash first <manifest>"))?;
        let mut out = crate::commands::output_writer(cli.output.as_deref())?;
        crate::commands::first_cmd::first_manifest(manifest.as_ref(), &mut out)?;
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

    // Build YARA scanner once if --yara was given (requires `yara` feature).
    #[cfg(feature = "yara")]
    let yara_scanner_instance: Option<blazehash::yara_scan::YaraScanner> =
        if let Some(ref rules_path) = cli.yara {
            Some(
                blazehash::yara_scan::YaraScanner::new(rules_path)
                    .with_context(|| format!("failed to compile YARA rules from {}", rules_path.display()))?,
            )
        } else {
            None
        };

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
        #[cfg(feature = "ots")]
        Mode::OtsStamp => unreachable!(),
        #[cfg(feature = "ots")]
        Mode::OtsVerify => unreachable!(),
        #[cfg(feature = "tui")]
        Mode::Tui => unreachable!(),
        Mode::Completions => unreachable!(),
        #[cfg(feature = "report")]
        Mode::Report => unreachable!(),
        Mode::Cosign => unreachable!(),
        Mode::VerifyMsig => unreachable!(),
        Mode::PqSign => unreachable!(),
        Mode::PqVerifySig => unreachable!(),
        Mode::Merkle => unreachable!(),
        Mode::MerkleProof => unreachable!(),
        Mode::MerkleVerify => unreachable!(),
        Mode::Disclose => unreachable!(),
        Mode::ProveMembership => unreachable!(),
        Mode::Timeline => unreachable!(),
        Mode::Lint => unreachable!(),
        Mode::Redact => unreachable!(),
        Mode::Sample => unreachable!(),
        Mode::Stats => unreachable!(),
        Mode::Filter => unreachable!(),
        Mode::Normalize => unreachable!(),
        Mode::Selfcheck => unreachable!(),
        Mode::Archive => unreachable!(),
        Mode::Convert => unreachable!(),
        Mode::Head => unreachable!(),
        Mode::Tail => unreachable!(),
        Mode::Search => unreachable!(),
        Mode::Export => unreachable!(),
        Mode::Sort => unreachable!(),
        Mode::Intersect => unreachable!(),
        Mode::Subtract => unreachable!(),
        Mode::ApplyPatch => unreachable!(),
        Mode::Verify => unreachable!(),
        Mode::Info => unreachable!(),
        Mode::Missing => unreachable!(),
        Mode::Tag => unreachable!(),
        Mode::Count => unreachable!(),
        Mode::Cat => unreachable!(),
        Mode::Split => unreachable!(),
        Mode::Uniq => unreachable!(),
        Mode::Checksum => unreachable!(),
        Mode::Pivot => unreachable!(),
        Mode::Rename => unreachable!(),
        Mode::Slice => unreachable!(),
        Mode::Stamp => unreachable!(),
        Mode::Grep => unreachable!(),
        Mode::Tally => unreachable!(),
        Mode::Exclude => unreachable!(),
        Mode::Contains => unreachable!(),
        Mode::PathOnly => unreachable!(),
        Mode::HashOnly => unreachable!(),
        Mode::Duplicates => unreachable!(),
        Mode::Repair => unreachable!(),
        Mode::SymDiff => unreachable!(),
        Mode::First => unreachable!(),
        Mode::Annotate => unreachable!(),
        Mode::Shuffle => unreachable!(),
        Mode::Reverse => unreachable!(),
        Mode::UniqueHash => unreachable!(),
        Mode::Balance => unreachable!(),
        Mode::Interleave => unreachable!(),
        #[cfg(feature = "remote")]
        Mode::GDriveCollect => {
            let input = cli.paths.first()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let file_id = blazehash::remote::gdrive::parse_file_id(&input)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Could not parse a Google Drive file ID from: {input}"
                    )
                })?;
            let mut out = crate::commands::output_writer(cli.output.as_deref())?;
            blazehash::remote::gdrive::hash_gdrive_file(&file_id, &algorithms, &mut *out)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        #[cfg(feature = "qr")]
        Mode::Qr => unreachable!(),
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
                cli.fail_on_unknown,
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
                #[cfg(feature = "hashdb")]
                nsrl_hsh: cli.nsrl_hsh.as_ref(),
                #[cfg(feature = "hashdb")]
                hashdb_bad: cli.hashdb_bad.as_ref(),
                sign: cli.sign,
                ads: cli.ads,
                entropy: cli.entropy,
                case_id: cli.case_id.as_deref(),
                examiner: cli.examiner.as_deref(),
                progress: cli.progress || std::io::IsTerminal::is_terminal(&std::io::stdout()),
                sector_size: cli.sector_size,
                #[cfg(feature = "yara")]
                yara_scanner: yara_scanner_instance.as_ref(),
                #[cfg(feature = "yara")]
                yara_max_size_mb: cli.yara_max_size,
            })?;
        }
    }

    Ok(())
}
