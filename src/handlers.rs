use serde_json::{json, Value};

pub fn handle_hash(_paths: &[String], _algorithms: &[String], _recursive: bool) -> Result<Value, String> {
    Err("not yet implemented".into())
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
