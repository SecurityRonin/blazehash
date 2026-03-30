# blazehash MCP Server Design

**Date:** 2026-03-30
**Status:** Approved

## Goal

Add an MCP (Model Context Protocol) server to blazehash, exposing hashing, audit, and forensic image verification capabilities over JSON-RPC stdio for AI-assisted forensic analysis. Follows the same pattern established in the ewf crate's MCP server.

## Architecture

### Single crate with `blazehash mcp` subcommand

blazehash remains a single crate (binary + library). Two new source files are added:

```
src/
  mcp.rs        -- JSON-RPC stdio loop (adapted from ewf mcp.rs)
  handlers.rs   -- One handler function per MCP tool
  main.rs       -- Add Mode::Mcp dispatch
  cli.rs        -- Add mcp mode detection
```

The `blazehash mcp` subcommand starts a JSON-RPC stdio server. `main.rs` dispatches `Mode::Mcp` to `mcp::run()`, which enters the stdio read loop. Each `tools/call` request is dispatched to a handler in `handlers.rs` that calls the blazehash library API and returns structured JSON.

### CLI integration

blazehash uses a flags-based CLI (`-a` for audit, `-s` for size-only, `--verify-image`, etc.) with positional path arguments. Rather than restructuring the entire CLI to use clap subcommands, `mcp` is detected as a special mode: if the first positional argument is the literal string `"mcp"`, enter MCP mode. This is minimal, non-breaking, and consistent with the ewf pattern from the user's perspective (`blazehash mcp`).

### JSON-RPC stdio protocol

Identical to the ewf MCP server:

- Line-delimited JSON-RPC 2.0 over stdin/stdout
- Supports `initialize`, `notifications/initialized`, `tools/list`, `tools/call`
- Protocol version: `2024-11-05`
- Server info: `{ "name": "blazehash", "version": "<CARGO_PKG_VERSION>" }`
- No framework dependency -- hand-rolled ~80-line loop using `serde_json`

## MCP Tools

### 1. `blazehash_hash`

Hash one or more files or directories with chosen algorithms.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `paths` | string[] | yes | -- | File or directory paths to hash |
| `algorithms` | string[] | no | `["blake3"]` | Hash algorithms to use |
| `recursive` | bool | no | `false` | Recurse into directories |

**Behavior:**
- For each path: if it's a file, hash it with `hash::hash_file()`. If it's a directory and `recursive` is true, use `walk::walk_and_hash()`. If it's a directory and `recursive` is false, hash only direct children that are files.
- Algorithm names are parsed via `Algorithm::from_str()` (case-insensitive, supports aliases like "sha-256").
- Invalid algorithm names return an error.

**Response:**
```json
{
  "files": [
    {
      "path": "/evidence/file.doc",
      "size": 12345,
      "hashes": { "blake3": "abc...", "sha256": "def..." }
    }
  ],
  "errors": [
    { "path": "/evidence/bad.doc", "error": "permission denied" }
  ]
}
```

### 2. `blazehash_audit`

Audit files against a known hash manifest, detecting matched, changed, new, moved, and missing files.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `paths` | string[] | yes | -- | File paths to audit |
| `manifest_path` | string | no | -- | Path to manifest file (hashdeep format) |
| `manifest_content` | string | no | -- | Inline manifest content |
| `recursive` | bool | no | `false` | Recurse into directory paths |

**Constraints:** Exactly one of `manifest_path` or `manifest_content` must be provided. If both or neither are given, return an error.

**Behavior:**
- If `manifest_path` is provided, read it with `fs::read_to_string()`.
- Expand directory paths in `paths` to individual file paths (using `walk::walk_paths()` if recursive).
- Call `audit::audit()` with the collected paths and manifest content.

**Response:**
```json
{
  "matched": 5,
  "changed": 1,
  "new_files": 2,
  "moved": 0,
  "missing": 1,
  "details": [
    { "status": "matched", "path": "/evidence/a.doc" },
    { "status": "changed", "path": "/evidence/b.doc" },
    { "status": "new", "path": "/evidence/c.doc" },
    { "status": "moved", "path": "/evidence/e.doc", "original": "/evidence/old_e.doc" },
    { "status": "missing", "path": "/evidence/d.doc" }
  ]
}
```

### 3. `blazehash_verify_image`

Verify a forensic disk image (E01/EWF) by recomputing media hashes and comparing against stored hashes.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `path` | string | yes | -- | Path to forensic image file (e.g. image.E01) |

**Behavior:**
- Calls `forensic_image::verify_image()` which auto-detects format from extension.
- Only available when the `forensic-image` feature is enabled (default).

**Response:**
```json
{
  "format": "EWF (E01)",
  "path": "/case/disk.E01",
  "media_size": 16106127360,
  "stored_md5": "abc...",
  "stored_sha1": "def...",
  "computed_md5": "abc...",
  "computed_sha1": "def...",
  "md5_match": true,
  "sha1_match": true,
  "metadata": {
    "case_number": "2024-001",
    "examiner": "J. Smith",
    "description": "Suspect laptop",
    "acquiry_software": "FTK Imager 4.7"
  }
}
```

### 4. `blazehash_algorithms`

List all supported hash algorithms and the default.

**Parameters:** None.

**Response:**
```json
{
  "algorithms": ["blake3", "sha256", "sha512", "sha3-256", "sha1", "md5", "tiger", "whirlpool"],
  "default": "blake3"
}
```

### 5. `blazehash_hash_bytes`

Hash raw inline data without writing to disk. Useful for AI agents that extract data from forensic images (via ewf MCP) and want to hash it directly.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `data` | string | yes | -- | Data to hash (hex-encoded or base64-encoded) |
| `encoding` | string | yes | -- | Encoding of `data`: `"hex"` or `"base64"` |
| `algorithms` | string[] | no | `["blake3"]` | Hash algorithms to use |

**Behavior:**
- Decode `data` from the specified encoding into bytes.
- Hash with `algorithm::hash_bytes()` for each requested algorithm.
- Invalid hex/base64 or unknown algorithms return an error.

**Response:**
```json
{
  "size": 512,
  "hashes": {
    "blake3": "abc...",
    "sha256": "def..."
  }
}
```

## Error Handling

Same pattern as ewf MCP:

- Each handler returns `Result<Value, String>`.
- `Ok(value)` becomes a successful MCP tool response with `content: [{ type: "text", text: pretty_json }]`.
- `Err(message)` becomes an MCP error response with `isError: true`.
- All library errors (anyhow) are caught and formatted as strings. No panics.
- JSON parse errors return JSON-RPC error code -32700.
- Unknown methods return JSON-RPC error code -32601.
- Unknown tool names return an MCP error (not a JSON-RPC error).

## Dependencies

No new dependencies required:
- `serde_json` -- already in Cargo.toml
- `serde` -- already in Cargo.toml
- Library functions -- already in `blazehash` lib

For base64 decoding in `blazehash_hash_bytes`, add the `base64` crate (lightweight, widely used).

## File Changes

| File | Change |
|------|--------|
| `src/mcp.rs` | New -- JSON-RPC stdio loop with tool definitions |
| `src/handlers.rs` | New -- handler functions for each MCP tool |
| `src/main.rs` | Modified -- add `Mode::Mcp` dispatch |
| `src/cli.rs` | Modified -- detect `mcp` as first positional arg |
| `Cargo.toml` | Modified -- add `base64` dependency |
| `README.md` | Modified -- add MCP server section |

## Testing

### Unit tests (handlers)

Each handler function is tested in isolation using tempfile fixtures:

- `blazehash_hash`: hash a temp file, verify JSON contains expected algorithms and non-empty hashes
- `blazehash_hash`: hash a temp directory recursively, verify multiple files returned
- `blazehash_audit`: create a manifest from known file, audit against it, verify matched=1
- `blazehash_audit`: modify file after manifest, verify changed=1
- `blazehash_audit`: test inline manifest_content parameter
- `blazehash_verify_image`: verify the E01 test fixture, check md5_match
- `blazehash_algorithms`: verify returns all 8 algorithms with "blake3" as default
- `blazehash_hash_bytes`: hash hex-encoded data, verify known vector
- `blazehash_hash_bytes`: hash base64-encoded data, verify same result
- Error cases: missing path, invalid algorithm, both/neither manifest params, invalid hex

### CLI integration tests (protocol)

Using `assert_cmd` to pipe JSON-RPC to `blazehash mcp`:

- Send `initialize`, verify protocol version and server info
- Send `tools/list`, verify all 5 tools present with correct schemas
- Send `tools/call` for `blazehash_hash`, verify response format
- Send `tools/call` for `blazehash_algorithms`, verify response
- Send invalid JSON, verify -32700 error
- Send unknown method, verify -32601 error

## Registration

### Claude Code
```bash
claude mcp add blazehash -- blazehash mcp
```

### Claude Desktop
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
