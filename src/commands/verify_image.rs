use anyhow::Result;
use blazehash::forensic_image::verify_image;
use blazehash::output::make_writer;
use std::io::Write;
use std::path::PathBuf;

pub fn run(paths: &[PathBuf], output: Option<&PathBuf>) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    for path in paths {
        let result = verify_image(path)?;
        write!(writer, "{result}")?;
    }

    writer.flush()?;
    Ok(())
}
