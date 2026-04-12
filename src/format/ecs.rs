use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use serde_json::json;
use std::io::Write;

fn ecs_hash_name(algo: &Algorithm) -> &'static str {
    match algo {
        Algorithm::Blake3 => "blake3",
        Algorithm::Sha256 => "sha256",
        Algorithm::Sha512 => "sha512",
        Algorithm::Sha3_256 => "sha3_256",
        Algorithm::Sha1 => "sha1",
        Algorithm::Md5 => "md5",
        Algorithm::Tiger => "tiger",
        Algorithm::Whirlpool => "whirlpool",
        Algorithm::Ssdeep => "ssdeep",
        Algorithm::Tlsh => "tlsh",
        Algorithm::Crc32c => "crc32c",
        Algorithm::Xxh3 => "xxh3",
        Algorithm::Shake128 => "shake128",
        Algorithm::Shake256 => "shake256",
    }
}

fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let mut y = 1970u32;
    let mut d = days as u32;
    loop {
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let months = [
        31u32,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mo = 1u32;
    for dim in &months {
        if d < *dim {
            break;
        }
        d -= dim;
        mo += 1;
    }
    format!("{y:04}-{mo:02}-{:02}T{h:02}:{m:02}:{s:02}.000Z", d + 1)
}

pub fn write_ecs<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    let timestamp = now_iso8601();
    for result in results {
        let mut hash_obj = serde_json::Map::new();
        for algo in algorithms {
            if let Some(hash) = result.hashes.get(algo) {
                hash_obj.insert(ecs_hash_name(algo).to_string(), json!(hash));
            }
        }
        let file_name = result
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        let mut file_obj = serde_json::Map::new();
        file_obj.insert("path".to_string(), json!(result.path.display().to_string()));
        file_obj.insert("name".to_string(), json!(file_name));
        file_obj.insert("size".to_string(), json!(result.size));
        file_obj.insert("hash".to_string(), serde_json::Value::Object(hash_obj));
        if let Some(entropy) = result.entropy {
            file_obj.insert("entropy".to_string(), json!(entropy));
        }
        let doc = json!({
            "@timestamp": timestamp,
            "event": {
                "kind": "enrichment",
                "category": ["file"],
                "type": ["info"],
                "module": "blazehash"
            },
            "file": file_obj,
        });
        serde_json::to_writer(&mut *w, &doc)?;
        writeln!(w)?;
    }
    Ok(())
}
