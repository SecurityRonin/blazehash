use crate::handlers;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn tool_definitions() -> Value {
    json!([
        {
            "name": "blazehash_hash",
            "description": "Hash one or more files or directories with chosen algorithms. Supports 8 algorithms: blake3, sha256, sha512, sha3-256, sha1, md5, tiger, whirlpool.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "File or directory paths to hash"
                    },
                    "algorithms": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Hash algorithms to use (default: [\"blake3\"])"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Recurse into directories (default: false)"
                    }
                },
                "required": ["paths"]
            }
        },
        {
            "name": "blazehash_audit",
            "description": "Audit files against a known hash manifest (hashdeep format). Detects matched, changed, new, moved, and missing files.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "File or directory paths to audit"
                    },
                    "manifest_path": {
                        "type": "string",
                        "description": "Path to manifest file (hashdeep format)"
                    },
                    "manifest_content": {
                        "type": "string",
                        "description": "Inline manifest content (hashdeep format)"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Recurse into directory paths (default: false)"
                    }
                },
                "required": ["paths"]
            }
        },
        {
            "name": "blazehash_verify_image",
            "description": "Verify a forensic disk image (E01/EWF) by recomputing media hashes and comparing against stored hashes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to forensic image file (e.g. image.E01)"
                    }
                },
                "required": ["path"]
            }
        },
        {
            "name": "blazehash_algorithms",
            "description": "List all supported hash algorithms and the default algorithm.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "blazehash_hash_bytes",
            "description": "Hash raw inline data (hex or base64 encoded) without writing to disk.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "Data to hash (hex-encoded or base64-encoded)"
                    },
                    "encoding": {
                        "type": "string",
                        "description": "Encoding of data: \"hex\" or \"base64\""
                    },
                    "algorithms": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Hash algorithms to use (default: [\"blake3\"])"
                    }
                },
                "required": ["data", "encoding"]
            }
        }
    ])
}

fn dispatch_tool(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        "blazehash_hash" => {
            let paths = args.get("paths")
                .and_then(|v| v.as_array())
                .ok_or("missing required parameter: paths")?
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>();
            if paths.is_empty() {
                return Err("paths must be a non-empty array of strings".into());
            }
            let algorithms = args.get("algorithms")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
                .unwrap_or_default();
            let recursive = args.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);
            handlers::handle_hash(&paths, &algorithms, recursive)
        }
        "blazehash_audit" => {
            let paths = args.get("paths")
                .and_then(|v| v.as_array())
                .ok_or("missing required parameter: paths")?
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>();
            let manifest_path = args.get("manifest_path").and_then(|v| v.as_str());
            let manifest_content = args.get("manifest_content").and_then(|v| v.as_str());
            let recursive = args.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);
            handlers::handle_audit(&paths, manifest_path, manifest_content, recursive)
        }
        "blazehash_verify_image" => {
            let path = args.get("path").and_then(|v| v.as_str())
                .ok_or("missing required parameter: path")?;
            handlers::handle_verify_image(path)
        }
        "blazehash_algorithms" => {
            handlers::handle_algorithms()
        }
        "blazehash_hash_bytes" => {
            let data = args.get("data").and_then(|v| v.as_str())
                .ok_or("missing required parameter: data")?;
            let encoding = args.get("encoding").and_then(|v| v.as_str())
                .ok_or("missing required parameter: encoding")?;
            let algorithms = args.get("algorithms")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
                .unwrap_or_default();
            handlers::handle_hash_bytes(data, encoding, &algorithms)
        }
        _ => Err(format!("unknown tool: {name}")),
    }
}

pub fn run() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.is_empty() {
            continue;
        }

        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err = json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": format!("Parse error: {e}")},
                    "id": null
                });
                let _ = writeln!(stdout, "{err}");
                continue;
            }
        };

        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "blazehash",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                },
                "id": id
            }),
            "notifications/initialized" => continue,
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "result": { "tools": tool_definitions() },
                "id": id
            }),
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));

                match dispatch_tool(tool_name, &args) {
                    Ok(result) => json!({
                        "jsonrpc": "2.0",
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                            }]
                        },
                        "id": id
                    }),
                    Err(e) => json!({
                        "jsonrpc": "2.0",
                        "result": {
                            "content": [{"type": "text", "text": e}],
                            "isError": true
                        },
                        "id": id
                    }),
                }
            }
            _ => json!({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": format!("Method not found: {method}")},
                "id": id
            }),
        };

        let _ = writeln!(stdout, "{response}");
        let _ = stdout.flush();
    }
}
