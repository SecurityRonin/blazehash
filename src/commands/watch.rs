use blazehash::algorithm::Algorithm;
use blazehash::manifest::ManifestRecord;
use blazehash::manifest_loader::load_manifest;
use blazehash::watch::{check_file_against_baseline, ChangeStatus};
use anyhow::Result;
use notify::{EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;

pub struct WatchArgs {
    pub path: PathBuf,
    pub manifest: PathBuf,
    pub algos: Vec<Algorithm>,
}

pub fn run_watch(args: WatchArgs) -> Result<()> {
    let records = load_manifest(&args.manifest)?;
    let baseline: HashMap<PathBuf, ManifestRecord> =
        records.into_iter().map(|r| (r.path.clone(), r)).collect();

    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(&args.path, RecursiveMode::Recursive)?;

    eprintln!(
        "[*] Watching {} against {}",
        args.path.display(),
        args.manifest.display()
    );
    eprintln!("[*] Press Ctrl+C to stop.");

    for event in rx {
        let event = event?;
        match event.kind {
            EventKind::Remove(_) => {
                for p in &event.paths {
                    eprintln!("[-] {}", p.display());
                }
            }
            EventKind::Create(_) | EventKind::Modify(_) => {
                for p in &event.paths {
                    if !p.is_file() {
                        continue;
                    }
                    match check_file_against_baseline(p, &baseline, &args.algos) {
                        Ok(ChangeStatus::New) => eprintln!("[+] {}", p.display()),
                        Ok(ChangeStatus::Modified) => eprintln!("[!] {}", p.display()),
                        Ok(ChangeStatus::Unchanged) => {}
                        Err(e) => eprintln!("[?] {} — {e}", p.display()),
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
