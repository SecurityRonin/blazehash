use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use serde_json::{json, Value};
use std::io::Write;

fn result_to_json(result: &FileHashResult, algorithms: &[Algorithm]) -> Value {
    let mut hashes = serde_json::Map::new();
    for algo in algorithms {
        if let Some(hash) = result.hashes.get(algo) {
            hashes.insert(algo.hashdeep_name().to_string(), json!(hash));
        }
    }
    json!({
        "filename": result.path.display().to_string(),
        "size": result.size,
        "hashes": hashes,
    })
}

pub fn write_json<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    let arr: Vec<Value> = results
        .iter()
        .map(|r| result_to_json(r, algorithms))
        .collect();
    serde_json::to_writer_pretty(&mut *w, &arr)?;
    writeln!(w)?;
    Ok(())
}

pub fn write_jsonl<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    for result in results {
        let val = result_to_json(result, algorithms);
        serde_json::to_writer(&mut *w, &val)?;
        writeln!(w)?;
    }
    Ok(())
}
