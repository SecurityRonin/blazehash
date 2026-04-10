# MCP Server

blazehash includes a built-in [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for AI-assisted forensic hashing. Connect it to Claude Code, Claude Desktop, Cursor, or any MCP-compatible AI agent.

---

## What is MCP

MCP is a standard protocol that lets AI agents call tools over JSON-RPC. Instead of asking an AI to "run this shell command," MCP gives the agent structured access to specific capabilities — hash files, audit manifests, verify images — with typed inputs and outputs.

blazehash exposes its core functionality as MCP tools. An AI agent can hash files, compare manifests, and verify disk images without needing shell access or knowing CLI flags.

---

## Setup

### Claude Code

```bash
claude mcp add blazehash -- blazehash mcp
```

### Claude Desktop

Add to your `claude_desktop_config.json`:

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

### Any MCP client

The server communicates over stdin/stdout using JSON-RPC 2.0. Start it with:

```bash
blazehash mcp
```

---

## Available tools

### `blazehash_hash`

Hash one or more files or directories.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `paths` | array of strings | Yes | — | Files or directories to hash |
| `algorithms` | array of strings | No | `["blake3"]` | Hash algorithms to compute |
| `recursive` | boolean | No | `false` | Recurse into directories |

**Example request:**

```json
{
  "method": "tools/call",
  "params": {
    "name": "blazehash_hash",
    "arguments": {
      "paths": ["/mnt/evidence"],
      "algorithms": ["blake3", "sha256"],
      "recursive": true
    }
  }
}
```

### `blazehash_audit`

Audit files against a known hash manifest. Detects matched, changed, new, moved, and missing files.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `paths` | array of strings | Yes | Directories to audit |
| `manifest_path` | string | One of these | Path to manifest file on disk |
| `manifest_content` | string | required | Manifest content as a string |
| `recursive` | boolean | No | Recurse into directories |

Exactly one of `manifest_path` or `manifest_content` must be provided.

**Example request:**

```json
{
  "method": "tools/call",
  "params": {
    "name": "blazehash_audit",
    "arguments": {
      "paths": ["/mnt/evidence"],
      "manifest_path": "/cases/case001/baseline.hash",
      "recursive": true
    }
  }
}
```

### `blazehash_verify_image`

Verify a forensic disk image (E01/EWF or raw/DD with sidecar hashes).

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | Path to the disk image file |

**Example request:**

```json
{
  "method": "tools/call",
  "params": {
    "name": "blazehash_verify_image",
    "arguments": {
      "path": "/cases/case001/disk.E01"
    }
  }
}
```

### `blazehash_algorithms`

List all supported hash algorithms and the default algorithm. Takes no parameters.

**Example request:**

```json
{
  "method": "tools/call",
  "params": {
    "name": "blazehash_algorithms",
    "arguments": {}
  }
}
```

### `blazehash_hash_bytes`

Hash raw inline data without writing to disk. Useful for hashing data the AI agent already has in memory.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `data` | string | Yes | — | Hex or base64 encoded data |
| `encoding` | string | No | `"hex"` | Input encoding: `"hex"` or `"base64"` |
| `algorithms` | array of strings | No | `["blake3"]` | Hash algorithms to compute |

**Example request:**

```json
{
  "method": "tools/call",
  "params": {
    "name": "blazehash_hash_bytes",
    "arguments": {
      "data": "48656c6c6f20576f726c64",
      "encoding": "hex",
      "algorithms": ["sha256", "blake3"]
    }
  }
}
```

---

## Example agent workflows

### "Hash this evidence folder and summarize what you find"

An AI agent calls `blazehash_hash` with `recursive: true`, receives structured results, and can summarize file counts, total size, and flag unusual files.

### "Check if anything changed since our last baseline"

The agent calls `blazehash_audit` with the previous manifest. The response includes categorized results (matched, changed, added, removed, moved) that the agent can present in natural language.

### "Verify this disk image before we start analysis"

The agent calls `blazehash_verify_image` on an E01 file and reports whether all checksums pass.

### "What algorithms should I use for court submission?"

The agent calls `blazehash_algorithms` to get the full list, then recommends `sha256` (universally accepted) plus `blake3` (fast, modern) based on the use case.

---

## JSON-RPC protocol details

The MCP server implements the [MCP specification](https://modelcontextprotocol.io/specification) over stdin/stdout.

### Initialization

The client sends an `initialize` request. The server responds with its capabilities:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "clientInfo": { "name": "my-client", "version": "1.0" }
  }
}
```

### Tool discovery

The client sends `tools/list` to discover available tools:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list"
}
```

The server responds with each tool's name, description, and JSON Schema for its parameters.

### Tool invocation

The client sends `tools/call` with the tool name and arguments:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "blazehash_hash",
    "arguments": {
      "paths": ["/tmp/test.txt"],
      "algorithms": ["sha256"]
    }
  }
}
```

The server responds with a `content` array containing text results:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "262144,a3f8e2c1d4b7...,/tmp/test.txt"
      }
    ]
  }
}
```

### Error handling

Tool errors return an `isError: true` response with an error message in the content, not a JSON-RPC error object. This follows the MCP convention of reporting tool-level failures as successful responses with error content.
