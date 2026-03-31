use blazehash::algorithm::Algorithm;

mod handler_tests {
    use super::*;

    #[test]
    fn algorithms_list_has_all_variants() {
        let all = Algorithm::all();
        assert_eq!(all.len(), 8);
        assert_eq!(all[0], Algorithm::Blake3);
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
            .stdout(predicate::str::contains(r#"\"default\": \"blake3\""#));
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
            .stdout(predicate::str::contains("test.txt"));
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
            .stdout(predicate::str::contains(r#"\"matched\": 1"#))
            .stdout(predicate::str::contains(r#"\"changed\": 0"#));
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
        // \\n in Rust string = literal \n chars, which JSON interprets as newlines
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
            .stdout(predicate::str::contains(r#"\"matched\": 1"#));
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
            .stdout(predicate::str::contains(r#"\"size\": 11"#));
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
            .stdout(predicate::str::contains(r#"\"size\": 11"#));
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
}
