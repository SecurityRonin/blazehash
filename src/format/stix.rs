use crate::algorithm::Algorithm;
use crate::hash::FileHashResult;
use anyhow::Result;
use serde_json::{json, Value};
use std::io::Write;
use uuid::Uuid;

// STIX SCO namespace: 00abedb4-aa42-466c-9c01-fed23315a9b7
const STIX_SCO_NAMESPACE: Uuid = Uuid::from_bytes([
    0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c, 0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7,
]);

fn stix_hash_name(algo: &Algorithm) -> &'static str {
    match algo {
        Algorithm::Blake3 => "BLAKE3",
        Algorithm::Sha256 => "SHA-256",
        Algorithm::Sha512 => "SHA-512",
        Algorithm::Sha3_256 => "SHA3-256",
        Algorithm::Sha1 => "SHA-1",
        Algorithm::Md5 => "MD5",
        Algorithm::Tiger => "TIGER",
        Algorithm::Whirlpool => "WHIRLPOOL",
        Algorithm::Ssdeep => "SSDEEP",
        Algorithm::Tlsh => "TLSH",
        Algorithm::Crc32c => "CRC32C",
        Algorithm::Xxh3 => "XXH3",
        Algorithm::Shake128 => "SHAKE128",
        Algorithm::Shake256 => "SHAKE256",
    }
}

fn result_to_stix_sco(result: &FileHashResult, algorithms: &[Algorithm]) -> Value {
    let mut hashes = serde_json::Map::new();
    for algo in algorithms {
        if let Some(hash) = result.hashes.get(algo) {
            hashes.insert(stix_hash_name(algo).to_string(), json!(hash));
        }
    }
    let hashes_json = serde_json::to_string(&hashes).unwrap_or_default();
    let id_input = format!("{{\"hashes\":{hashes_json}}}");
    let uuid = Uuid::new_v5(&STIX_SCO_NAMESPACE, id_input.as_bytes());
    let stix_id = format!("file--{uuid}");
    let file_name = result
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    json!({
        "type": "file",
        "spec_version": "2.1",
        "id": stix_id,
        "hashes": hashes,
        "size": result.size,
        "name": file_name,
    })
}

pub fn write_stix<W: Write>(
    w: &mut W,
    results: &[FileHashResult],
    algorithms: &[Algorithm],
) -> Result<()> {
    let mut objects: Vec<Value> = results
        .iter()
        .map(|r| result_to_stix_sco(r, algorithms))
        .collect();

    // Enrich with x-mitre-attack extension objects for any YARA matches.
    #[cfg(feature = "yara")]
    {
        use crate::attack::lookup_attack;
        for result in results {
            if let Some(ref matches) = result.yara_matches {
                let file_name = result
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                let file_path = result.path.to_string_lossy();
                for rule_name in matches {
                    if let Some(technique) = lookup_attack(rule_name) {
                        let id_input = format!("{}-{}-{}", file_path, technique.technique_id, rule_name);
                        let uuid = Uuid::new_v5(&Uuid::NAMESPACE_URL, id_input.as_bytes());
                        objects.push(json!({
                            "type": "x-mitre-attack",
                            "id": format!("x-mitre-attack--{uuid}"),
                            "spec_version": "2.1",
                            "technique_id": technique.technique_id,
                            "tactic": technique.tactic,
                            "technique_name": technique.name,
                            "yara_rule": rule_name,
                            "related_file": file_name,
                        }));
                    }
                }
            }
        }
    }

    let bundle_uuid = Uuid::new_v5(
        &STIX_SCO_NAMESPACE,
        format!("blazehash-bundle-{}", objects.len()).as_bytes(),
    );
    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{bundle_uuid}"),
        "spec_version": "2.1",
        "objects": objects,
    });
    serde_json::to_writer_pretty(&mut *w, &bundle)?;
    writeln!(w)?;
    Ok(())
}
