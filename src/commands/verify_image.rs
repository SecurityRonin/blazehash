use anyhow::{bail, Result};
use blazehash::forensic_image::{verify_image, ImageFormat};
use blazehash::output::make_writer;
use std::io::Write;
use std::path::PathBuf;

pub fn run(paths: &[PathBuf], output: Option<&PathBuf>) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    for path in paths {
        let result = verify_image(path)?;

        if result.format == ImageFormat::RawDd {
            // Render sidecar results with [+]/[!] indicators.
            let mut any_mismatch = false;

            for sr in &result.sidecar_results {
                if sr.is_match() {
                    writeln!(
                        writer,
                        "[+] {} {} verified ({})",
                        path.display(),
                        sr.algo,
                        sr.computed
                    )?;
                } else {
                    writeln!(
                        writer,
                        "[!] {} {} MISMATCH — expected {} got {}",
                        path.display(),
                        sr.algo,
                        sr.expected,
                        sr.computed
                    )?;
                    any_mismatch = true;
                }
            }

            writer.flush()?;

            if any_mismatch {
                bail!("hash mismatch detected for {}", path.display());
            }
        } else {
            write!(writer, "{result}")?;
        }
    }

    writer.flush()?;
    Ok(())
}
