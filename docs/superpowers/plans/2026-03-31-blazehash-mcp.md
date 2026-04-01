# blazehash MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an MCP server to blazehash exposing hashing, audit, and forensic image verification over JSON-RPC stdio.

**Architecture:** Two new files (`src/mcp.rs`, `src/handlers.rs`) plus modifications to `src/cli.rs` and `src/main.rs`. The `blazehash mcp` command enters a stdio JSON-RPC loop. Each tool dispatches to a handler that calls the blazehash library API and returns `serde_json::Value`. Pattern copied from the ewf MCP server.

**Tech Stack:** Rust, serde_json (already a dependency), base64 (new), blazehash library crate.

---

## File Structure

| File | Responsibility |
|------|---------------|
| `src/handlers.rs` | NEW — One `handle_*` function per MCP tool. Pure functions: take parsed args, call library, return `Result<Value, String>`. |
| `src/mcp.rs` | NEW — JSON-RPC stdio loop. Tool definitions array. `dispatch_tool()` match. `run()` entry point. |
| `src/cli.rs` | MODIFY — Add `Mode::Mcp` variant, detect "mcp" as first positional arg. |
| `src/main.rs` | MODIFY — Add `Mode::Mcp => mcp::run()` dispatch arm. |
| `Cargo.toml` | MODIFY — Add `base64` dependency. |
| `tests/mcp_tests.rs` | NEW — Handler unit tests and CLI protocol integration tests. |
| `README.md` | MODIFY — Add MCP server section. |

---

### Task 1: Add `base64` dependency and `Mode::Mcp` to CLI

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/cli.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Add base64 dependency to Cargo.toml**

In `Cargo.toml`, add to the `[dependencies]` section:

```toml
base64 = "0.22"
```

- [ ] **Step 2: Add `Mode::Mcp` to cli.rs**

In `src/cli.rs`, add `Mcp` to the `Mode` enum (line 86-92):

```rust
#[derive(Debug)]
pub enum Mode {
    Mcp,
    SizeOnly,
    Audit,
    VerifyImage,
    Piecewise,
    Hash,
}
```

Change the `#[arg]` attribute on `paths` to not require paths when mcp mode is used. Replace line 14:

```rust
    #[arg()]
    pub paths: Vec<PathBuf>,
```

Update the `mode()` method to check for "mcp" as the first positional arg (must be checked first, before all other flags):

```rust
    pub fn mode(&self) -> Mode {
        if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("mcp")) {
            Mode::Mcp
        } else if self.size_only {
            Mode::SizeOnly
        } else if self.audit {
            Mode::Audit
        } else if self.verify_image {
            Mode::VerifyImage
        } else if self.piecewise.is_some() {
            Mode::Piecewise
        } else {
            Mode::Hash
        }
    }
```

- [ ] **Step 3: Add Mcp dispatch to main.rs**

In `src/main.rs`, add `mod mcp;` and `mod handlers;` at the top (after `mod commands;`), and add the `Mode::Mcp` match arm as the first arm (before SizeOnly):

```rust
mod cli;
mod commands;
mod handlers;
mod mcp;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Mode};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.mode() {
        Mode::Mcp => {
            mcp::run();
            return Ok(());
        }
        _ => {}
    }

    let algorithms = cli.flat_algorithms();

    match cli.mode() {
        Mode::Mcp => unreachable!(),
        Mode::SizeOnly => {
            commands::size_only::run(&cli.paths, cli.recursive, cli.output.as_ref())?;
        }
        Mode::Audit => {
            commands::audit::run(&cli.paths, &cli.known, cli.recursive, cli.output.as_ref())?;
        }
        Mode::VerifyImage => {
            commands::verify_image::run(&cli.paths, cli.output.as_ref())?;
        }
        Mode::Piecewise => {
            let chunk_str = cli.piecewise.as_ref().unwrap();
            commands::piecewise::run(
                &cli.paths,
                &algorithms,
                chunk_str,
                cli.bare,
                cli.output.as_ref(),
            )?;
        }
        Mode::Hash => {
            commands::hash::run(
                &cli.paths,
                &algorithms,
                cli.recursive,
                &cli.format,
                cli.bare,
                cli.resume,
                cli.output.as_ref(),
            )?;
        }
    }

    Ok(())
}
```

- [ ] **Step 4: Create stub mcp.rs and handlers.rs so it compiles**

Create `src/mcp.rs`:

```rust
pub fn run() {
    // Will be implemented in Task 2
    eprintln!("MCP server not yet implemented");
}
```

Create `src/handlers.rs`:

```rust
// Will be implemented in Tasks 3-7
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo build`
Expected: Compiles with no errors (warnings are OK).

- [ ] **Step 6: Verify `blazehash mcp` enters MCP mode**

Run: `echo '' | cargo run -- mcp 2>&1`
Expected: Output contains "MCP server not yet implemented"

- [ ] **Step 7: Verify existing CLI still works**

Run: `cargo test -p blazehash`
Expected: All existing tests pass.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml src/cli.rs src/main.rs src/mcp.rs src/handlers.rs
git commit -m "feat: add Mode::Mcp and blazehash mcp subcommand stub"
```

---

### Task 2: Implement MCP JSON-RPC stdio loop

**Files:**
- Create: `src/mcp.rs`

- [ ] **Step 1: Write the full mcp.rs**

Replace the contents of `src/mcp.rs` with the JSON-RPC stdio loop. This follows the exact pattern from the ewf MCP server:

```rust
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
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles (handlers.rs is still empty stubs — `dispatch_tool` references functions that don't exist yet, so this will fail until Task 3 is done. If so, add stub signatures to handlers.rs.)

Create temporary stubs in `src/handlers.rs` so it compiles:

```rust
use serde_json::Value;

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
    Err("not yet implemented".into())
}

pub fn handle_hash_bytes(_data: &str, _encoding: &str, _algorithms: &[String]) -> Result<Value, String> {
    Err("not yet implemented".into())
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles with no errors.

- [ ] **Step 4: Commit**

```bash
git add src/mcp.rs src/handlers.rs
git commit -m "feat: implement MCP JSON-RPC stdio loop with tool definitions"
```

---

### Task 3: Implement `blazehash_algorithms` handler

**Files:**
- Modify: `src/handlers.rs`
- Create: `tests/mcp_tests.rs`

- [ ] **Step 1: Write the failing test**

Create `tests/mcp_tests.rs`:

```rust
use blazehash::algorithm::Algorithm;

mod handler_tests {
    use super::*;

    // We test handlers by calling the library functions directly,
    // since handlers.rs is in the binary crate (not the library).
    // For handler-level tests, we use CLI integration tests below.

    #[test]
    fn algorithms_list_has_all_variants() {
        let all = Algorithm::all();
        assert_eq!(all.len(), 8);
        assert_eq!(all[0], Algorithm::Blake3); // default is first
    }
}

mod protocol_tests {
    use assert_cmd::Command;
    use predicates::prelude::*;

    fn mcp_command() -> Command {
        let mut cmd = Command::cargo_bin("blazehash").unwrap();
        cmd.arg("mcp");
        cmd
    }

    #[test]
    fn mcp_initialize_returns_server_info() {
        let input = r#"{"jsonrpc":"2.0","method":"initialize","id":1}"#;
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("blazehash"))
            .stdout(predicate::str::contains("2024-11-05"));
    }

    #[test]
    fn mcp_tools_list_returns_all_tools() {
        let input = r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#;
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("blazehash_hash"))
            .stdout(predicate::str::contains("blazehash_audit"))
            .stdout(predicate::str::contains("blazehash_verify_image"))
            .stdout(predicate::str::contains("blazehash_algorithms"))
            .stdout(predicate::str::contains("blazehash_hash_bytes"));
    }

    #[test]
    fn mcp_algorithms_returns_all_eight() {
        let input = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"blazehash_algorithms","arguments":{}},"id":3}"#;
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("blake3"))
            .stdout(predicate::str::contains("sha256"))
            .stdout(predicate::str::contains("whirlpool"))
            .stdout(predicate::str::contains("\"default\": \"blake3\""));
    }

    #[test]
    fn mcp_invalid_json_returns_parse_error() {
        let input = "not valid json\n";
        mcp_command()
            .write_stdin(input)
            .assert()
            .success()
            .stdout(predicate::str::contains("-32700"));
    }

    #[test]
    fn mcp_unknown_method_returns_error() {
        let input = r#"{"jsonrpc":"2.0","method":"foo/bar","id":4}"#;
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("-32601"));
    }

    #[test]
    fn mcp_unknown_tool_returns_error() {
        let input = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"nonexistent","arguments":{}},"id":5}"#;
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("unknown tool"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test mcp_tests`
Expected: `mcp_algorithms_returns_all_eight` FAILS (handler returns "not yet implemented").

- [ ] **Step 3: Implement handle_algorithms**

Replace the `handle_algorithms` stub in `src/handlers.rs`:

```rust
pub fn handle_algorithms() -> Result<Value, String> {
    use blazehash::algorithm::Algorithm;

    let names: Vec<&str> = Algorithm::all().iter().map(|a| a.hashdeep_name()).collect();
    Ok(json!({
        "algorithms": names,
        "default": "blake3"
    }))
}
```

Add the required import at the top of `src/handlers.rs`:

```rust
use serde_json::{json, Value};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test mcp_tests`
Expected: All 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/handlers.rs tests/mcp_tests.rs
git commit -m "feat: implement blazehash_algorithms MCP tool with protocol tests"
```

---

### Task 4: Implement `blazehash_hash` handler

**Files:**
- Modify: `src/handlers.rs`
- Modify: `tests/mcp_tests.rs`

- [ ] **Step 1: Write the failing test**

Add to the `protocol_tests` module in `tests/mcp_tests.rs`:

```rust
    #[test]
    fn mcp_hash_file_returns_hashes() {
        use std::fs;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, b"hello world").unwrap();

        let input = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"blazehash_hash","arguments":{{"paths":["{}"]}}}},"id":10}}"#,
            file.display()
        );
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("blake3"))
            .stdout(predicate::str::contains("test.txt"))
            .stdout(predicate::str::contains("\"size\": 11"));
    }

    #[test]
    fn mcp_hash_file_with_multiple_algorithms() {
        use std::fs;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, b"hello world").unwrap();

        let input = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"blazehash_hash","arguments":{{"paths":["{}"],"algorithms":["blake3","sha256"]}}}},"id":11}}"#,
            file.display()
        );
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("blake3"))
            .stdout(predicate::str::contains("sha256"));
    }

    #[test]
    fn mcp_hash_directory_recursive() {
        use std::fs;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("b.txt"), b"bbb").unwrap();

        let input = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"blazehash_hash","arguments":{{"paths":["{}"],"recursive":true}}}},"id":12}}"#,
            dir.path().display()
        );
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("a.txt"))
            .stdout(predicate::str::contains("b.txt"));
    }

    #[test]
    fn mcp_hash_invalid_algorithm_returns_error() {
        use std::fs;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, b"hello").unwrap();

        let input = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"blazehash_hash","arguments":{{"paths":["{}"],"algorithms":["xxhash"]}}}},"id":13}}"#,
            file.display()
        );
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("isError"))
            .stdout(predicate::str::contains("unknown algorithm"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test mcp_tests mcp_hash`
Expected: FAIL — handler returns "not yet implemented".

- [ ] **Step 3: Implement handle_hash**

Replace the `handle_hash` stub in `src/handlers.rs`:

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test mcp_tests mcp_hash`
Expected: All 4 hash tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/handlers.rs tests/mcp_tests.rs
git commit -m "feat: implement blazehash_hash MCP tool"
```

---

### Task 5: Implement `blazehash_audit` handler

**Files:**
- Modify: `src/handlers.rs`
- Modify: `tests/mcp_tests.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `protocol_tests` module in `tests/mcp_tests.rs`:

```rust
    #[test]
    fn mcp_audit_matched_file() {
        use blazehash::algorithm::Algorithm;
        use blazehash::hash::hash_file;
        use std::fs;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, b"hello world").unwrap();

        let result = hash_file(&file, &[Algorithm::Blake3]).unwrap();
        let hash = result.hashes[&Algorithm::Blake3].clone();
        let manifest = format!(
            "%%%% HASHDEEP-1.0\n%%%% size,blake3,filename\n{},{},{}\n",
            result.size, hash, file.display()
        );
        let manifest_file = dir.path().join("manifest.hash");
        fs::write(&manifest_file, &manifest).unwrap();

        let input = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"blazehash_audit","arguments":{{"paths":["{}"],"manifest_path":"{}"}}}},"id":20}}"#,
            file.display(), manifest_file.display()
        );
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("\"matched\": 1"))
            .stdout(predicate::str::contains("\"changed\": 0"));
    }

    #[test]
    fn mcp_audit_with_inline_manifest() {
        use blazehash::algorithm::Algorithm;
        use blazehash::hash::hash_file;
        use std::fs;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, b"hello world").unwrap();

        let result = hash_file(&file, &[Algorithm::Blake3]).unwrap();
        let hash = result.hashes[&Algorithm::Blake3].clone();
        let manifest = format!(
            "%%%% HASHDEEP-1.0\\n%%%% size,blake3,filename\\n{},{},{}\\n",
            result.size, hash, file.display()
        );

        let input = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"blazehash_audit","arguments":{{"paths":["{}"],"manifest_content":"{}"}}}}, "id":21}}"#,
            file.display(), manifest
        );
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("\"matched\": 1"));
    }

    #[test]
    fn mcp_audit_no_manifest_returns_error() {
        use std::fs;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, b"hello").unwrap();

        let input = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"blazehash_audit","arguments":{{"paths":["{}"]}}}},"id":22}}"#,
            file.display()
        );
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("isError"))
            .stdout(predicate::str::contains("manifest_path or manifest_content"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test mcp_tests mcp_audit`
Expected: FAIL — handler returns "not yet implemented".

- [ ] **Step 3: Implement handle_audit**

Replace the `handle_audit` stub in `src/handlers.rs`:

```rust
pub fn handle_audit(
    paths: &[String],
    manifest_path: Option<&str>,
    manifest_content: Option<&str>,
    recursive: bool,
) -> Result<Value, String> {
    use blazehash::audit::{audit, AuditStatus};
    use blazehash::walk::walk_paths;
    use std::path::PathBuf;

    let manifest = match (manifest_path, manifest_content) {
        (Some(path), None) => {
            std::fs::read_to_string(path).map_err(|e| format!("failed to read manifest: {e}"))?
        }
        (None, Some(content)) => content.to_string(),
        (Some(_), Some(_)) => {
            return Err("provide either manifest_path or manifest_content, not both".into());
        }
        (None, None) => {
            return Err("must provide manifest_path or manifest_content".into());
        }
    };

    let mut file_paths: Vec<PathBuf> = Vec::new();
    for path_str in paths {
        let path = PathBuf::from(path_str);
        if path.is_dir() {
            let (found, _) = walk_paths(&path, recursive);
            file_paths.extend(found);
        } else {
            file_paths.push(path);
        }
    }

    let result = audit(&file_paths, &manifest).map_err(|e| e.to_string())?;

    let details: Vec<Value> = result.details.iter().map(|d| match d {
        AuditStatus::Matched(p) => json!({"status": "matched", "path": p.display().to_string()}),
        AuditStatus::Changed(p) => json!({"status": "changed", "path": p.display().to_string()}),
        AuditStatus::New(p) => json!({"status": "new", "path": p.display().to_string()}),
        AuditStatus::Moved { path, original } => json!({
            "status": "moved",
            "path": path.display().to_string(),
            "original": original.display().to_string()
        }),
        AuditStatus::Missing(p) => json!({"status": "missing", "path": p.display().to_string()}),
    }).collect();

    Ok(json!({
        "matched": result.matched,
        "changed": result.changed,
        "new_files": result.new_files,
        "moved": result.moved,
        "missing": result.missing,
        "details": details
    }))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test mcp_tests mcp_audit`
Expected: All 3 audit tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/handlers.rs tests/mcp_tests.rs
git commit -m "feat: implement blazehash_audit MCP tool"
```

---

### Task 6: Implement `blazehash_verify_image` handler

**Files:**
- Modify: `src/handlers.rs`
- Modify: `tests/mcp_tests.rs`

- [ ] **Step 1: Write the failing test**

Add to the `protocol_tests` module in `tests/mcp_tests.rs`:

```rust
    #[test]
    fn mcp_verify_image_returns_result() {
        let e01_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/nps-2010-emails.E01");

        let input = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"blazehash_verify_image","arguments":{{"path":"{e01_path}"}}}},"id":30}}"#,
        );
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("EWF"))
            .stdout(predicate::str::contains("md5_match"))
            .stdout(predicate::str::contains("media_size"));
    }

    #[test]
    fn mcp_verify_image_unsupported_format() {
        let input = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"blazehash_verify_image","arguments":{"path":"/tmp/fake.raw"}},"id":31}"#;
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("isError"))
            .stdout(predicate::str::contains("unsupported"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test mcp_tests mcp_verify_image`
Expected: FAIL — handler returns "not yet implemented".

- [ ] **Step 3: Implement handle_verify_image**

Replace the `handle_verify_image` stub in `src/handlers.rs`:

```rust
pub fn handle_verify_image(path: &str) -> Result<Value, String> {
    use blazehash::forensic_image::verify_image;
    use std::path::Path;

    let result = verify_image(Path::new(path)).map_err(|e| e.to_string())?;

    let metadata = result.metadata.as_ref().map(|m| json!({
        "case_number": m.case_number,
        "examiner": m.examiner,
        "description": m.description,
        "acquiry_software": m.acquiry_software,
    }));

    Ok(json!({
        "format": result.format.to_string(),
        "path": result.path,
        "media_size": result.media_size,
        "stored_md5": result.stored_md5,
        "stored_sha1": result.stored_sha1,
        "computed_md5": result.computed_md5,
        "computed_sha1": result.computed_sha1,
        "md5_match": result.md5_match,
        "sha1_match": result.sha1_match,
        "metadata": metadata
    }))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test mcp_tests mcp_verify_image`
Expected: Both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/handlers.rs tests/mcp_tests.rs
git commit -m "feat: implement blazehash_verify_image MCP tool"
```

---

### Task 7: Implement `blazehash_hash_bytes` handler

**Files:**
- Modify: `src/handlers.rs`
- Modify: `tests/mcp_tests.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `protocol_tests` module in `tests/mcp_tests.rs`:

```rust
    #[test]
    fn mcp_hash_bytes_hex_encoding() {
        // "hello world" = 68656c6c6f20776f726c64
        let input = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"blazehash_hash_bytes","arguments":{"data":"68656c6c6f20776f726c64","encoding":"hex","algorithms":["blake3"]}},"id":40}"#;
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("blake3"))
            .stdout(predicate::str::contains("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"))
            .stdout(predicate::str::contains("\"size\": 11"));
    }

    #[test]
    fn mcp_hash_bytes_base64_encoding() {
        // "hello world" = aGVsbG8gd29ybGQ=
        let input = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"blazehash_hash_bytes","arguments":{"data":"aGVsbG8gd29ybGQ=","encoding":"base64","algorithms":["blake3"]}},"id":41}"#;
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"))
            .stdout(predicate::str::contains("\"size\": 11"));
    }

    #[test]
    fn mcp_hash_bytes_invalid_hex() {
        let input = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"blazehash_hash_bytes","arguments":{"data":"ZZZZ","encoding":"hex"}},"id":42}"#;
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("isError"));
    }

    #[test]
    fn mcp_hash_bytes_invalid_encoding() {
        let input = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"blazehash_hash_bytes","arguments":{"data":"abc","encoding":"rot13"}},"id":43}"#;
        mcp_command()
            .write_stdin(format!("{input}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains("isError"))
            .stdout(predicate::str::contains("encoding"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test mcp_tests mcp_hash_bytes`
Expected: FAIL — handler returns "not yet implemented".

- [ ] **Step 3: Implement handle_hash_bytes**

Replace the `handle_hash_bytes` stub in `src/handlers.rs`:

```rust
pub fn handle_hash_bytes(data: &str, encoding: &str, algorithms: &[String]) -> Result<Value, String> {
    use base64::Engine;
    use blazehash::algorithm::{hash_bytes, Algorithm};
    use std::str::FromStr;

    let bytes = match encoding {
        "hex" => hex::decode(data).map_err(|e| format!("invalid hex: {e}"))?,
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| format!("invalid base64: {e}"))?,
        other => return Err(format!("unsupported encoding: {other} (use \"hex\" or \"base64\")")),
    };

    let algos: Vec<Algorithm> = if algorithms.is_empty() {
        vec![Algorithm::Blake3]
    } else {
        algorithms.iter()
            .map(|s| Algorithm::from_str(s).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?
    };

    let mut hashes = serde_json::Map::new();
    for algo in &algos {
        hashes.insert(algo.to_string(), json!(hash_bytes(*algo, &bytes)));
    }

    Ok(json!({
        "size": bytes.len(),
        "hashes": hashes
    }))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --test mcp_tests mcp_hash_bytes`
Expected: All 4 hash_bytes tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `cargo test`
Expected: ALL tests pass (existing + new MCP tests).

- [ ] **Step 6: Commit**

```bash
git add src/handlers.rs tests/mcp_tests.rs
git commit -m "feat: implement blazehash_hash_bytes MCP tool"
```

---

### Task 8: Update README with MCP documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add MCP section to README.md**

After the existing CLI usage section in `README.md`, add an MCP server section. Find the appropriate insertion point (after the CLI usage examples, before the detailed features section) and add:

```markdown
## MCP server

The `blazehash mcp` command starts an [MCP](https://modelcontextprotocol.io/) server for AI-assisted forensic hashing over JSON-RPC stdio.

| Tool | Description |
|------|-------------|
| `blazehash_hash` | Hash files/directories with configurable algorithms (default: BLAKE3) |
| `blazehash_audit` | Audit files against a known manifest — detect changes, moves, missing files |
| `blazehash_verify_image` | Verify forensic disk image integrity (E01/EWF) |
| `blazehash_algorithms` | List all 8 supported hash algorithms |
| `blazehash_hash_bytes` | Hash raw inline data (hex or base64 encoded) |

### Register with Claude Code

```bash
claude mcp add blazehash -- blazehash mcp
```

### Claude Desktop configuration

```json
{
  "mcpServers": {
    "blazehash": {
      "command": "blazehash",
      "args": ["mcp"]
    }
  }
}
```
```

- [ ] **Step 2: Verify the README renders correctly**

Skim the full README to make sure the new section fits naturally.

- [ ] **Step 3: Run full test suite one final time**

Run: `cargo test`
Expected: ALL tests pass.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: add MCP server section to README"
```
