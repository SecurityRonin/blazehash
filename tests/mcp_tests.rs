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
}
