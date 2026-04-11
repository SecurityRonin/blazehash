use anyhow::Result;
use blazehash::algorithm::Algorithm;
use blazehash::format::{write_csv, write_dfxml, write_json, write_jsonl, write_sumfile};
use blazehash::hash::FileHashResult;
use blazehash::manifest::{write_header, write_record};
use blazehash::output::make_writer;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;

pub fn run(
    algorithms: &[Algorithm],
    format: &str,
    bare: bool,
    output: Option<&std::path::PathBuf>,
) -> Result<()> {
    let mut writer = make_writer(output.map(|p| p.as_path()), false)?;

    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data)?;

    let size = data.len() as u64;
    let mut hashes = HashMap::new();
    for algo in algorithms {
        let hash = blazehash::algorithm::hash_bytes(*algo, &data);
        hashes.insert(*algo, hash);
    }

    let result = FileHashResult {
        path: PathBuf::from("<stdin>"),
        size,
        hashes,
        entropy: None,
    };

    match format {
        "csv" => write_csv(&mut writer, &[result], algorithms)?,
        "dfxml" => write_dfxml(&mut writer, &[result], algorithms)?,
        "json" => write_json(&mut writer, &[result], algorithms)?,
        "jsonl" => write_jsonl(&mut writer, &[result], algorithms)?,
        "sha256sum" | "md5sum" => write_sumfile(&mut writer, &[result], algorithms)?,
        _ => {
            if !bare {
                write_header(&mut writer, algorithms)?;
            }
            write_record(&mut writer, &result, algorithms)?;
        }
    }

    writer.flush()?;
    Ok(())
}
