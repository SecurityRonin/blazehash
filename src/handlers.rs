use serde_json::{json, Value};

pub fn handle_hash(paths: &[String], algorithms: &[String], recursive: bool) -> Result<Value, String> {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use blazehash::walk::walk_and_hash;
    use std::path::Path;
    use std::str::FromStr;

    let algos: Vec<Algorithm> = if algorithms.is_empty() {
        vec![Algorithm::Blake3]
    } else {
        algorithms.iter()
            .map(|s| Algorithm::from_str(s).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?
    };

    let mut files = Vec::new();
    let mut errors = Vec::new();

    for path_str in paths {
        let path = Path::new(path_str);
        if path.is_dir() {
            match walk_and_hash(path, &algos, recursive) {
                Ok(output) => {
                    for r in output.results {
                        let hashes: serde_json::Map<String, Value> = r.hashes.iter()
                            .map(|(a, h)| (a.to_string(), json!(h)))
                            .collect();
                        files.push(json!({
                            "path": r.path.display().to_string(),
                            "size": r.size,
                            "hashes": hashes
                        }));
                    }
                    for e in output.errors {
                        errors.push(json!({
                            "path": e.path.display().to_string(),
                            "error": e.error
                        }));
                    }
                }
                Err(e) => {
                    errors.push(json!({ "path": path_str, "error": e.to_string() }));
                }
            }
        } else {
            match hash_file(path, &algos) {
                Ok(r) => {
                    let hashes: serde_json::Map<String, Value> = r.hashes.iter()
                        .map(|(a, h)| (a.to_string(), json!(h)))
                        .collect();
                    files.push(json!({
                        "path": r.path.display().to_string(),
                        "size": r.size,
                        "hashes": hashes
                    }));
                }
                Err(e) => {
                    errors.push(json!({ "path": path_str, "error": e.to_string() }));
                }
            }
        }
    }

    Ok(json!({ "files": files, "errors": errors }))
}

pub fn handle_audit(_paths: &[String], _manifest_path: Option<&str>, _manifest_content: Option<&str>, _recursive: bool) -> Result<Value, String> {
    Err("not yet implemented".into())
}

pub fn handle_verify_image(_path: &str) -> Result<Value, String> {
    Err("not yet implemented".into())
}

pub fn handle_algorithms() -> Result<Value, String> {
    use blazehash::algorithm::Algorithm;

    let names: Vec<&str> = Algorithm::all().iter().map(|a| a.hashdeep_name()).collect();
    Ok(json!({
        "algorithms": names,
        "default": "blake3"
    }))
}

pub fn handle_hash_bytes(_data: &str, _encoding: &str, _algorithms: &[String]) -> Result<Value, String> {
    Err("not yet implemented".into())
}
