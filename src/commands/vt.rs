use blazehash::algorithm::Algorithm;
use blazehash::manifest_loader::load_manifest;
use blazehash::vt::{classify_vt_response, VtResult};
use anyhow::Result;
use std::path::PathBuf;
use std::time::Duration;

pub struct VtArgs {
    pub manifest: PathBuf,
    pub api_key: String,
}

pub fn run_vt(args: VtArgs) -> Result<()> {
    let records = load_manifest(&args.manifest)?;

    for record in &records {
        // VT requires SHA-256; look it up directly by Algorithm key.
        let sha256 = match record.hashes.get(&Algorithm::Sha256) {
            Some(h) => h.as_str(),
            None => {
                println!(
                    "[skip] {} -- no SHA-256 hash available",
                    record.path.display()
                );
                continue;
            }
        };

        let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
        let response = ureq::get(&url).set("x-apikey", &args.api_key).call();

        let label = match response {
            Ok(r) => {
                let json: serde_json::Value = r.into_json()?;
                match classify_vt_response(&json) {
                    VtResult::Clean(n) => format!("[clean {n}]"),
                    VtResult::Malicious { count, total } => {
                        format!("[malicious {count}/{total}]")
                    }
                    VtResult::Unknown => "[unknown]".to_string(),
                }
            }
            Err(ureq::Error::Status(404, _)) => "[unknown]".to_string(),
            Err(e) => format!("[error: {e}]"),
        };

        println!("{label} {}", record.path.display());
        std::thread::sleep(Duration::from_millis(250)); // 4 req/s
    }

    Ok(())
}
