#[cfg(feature = "remote")]
mod remote_writer_tests {
    use blazehash::remote::writer::RemoteWriter;
    use opendal::{blocking, services, Operator};
    use std::io::Write;

    fn make_rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn mem_op() -> (tokio::runtime::Runtime, blocking::Operator) {
        let rt = make_rt();
        let op = {
            let _guard = rt.enter();
            let async_op = Operator::new(services::Memory::default()).unwrap().finish();
            blocking::Operator::new(async_op).unwrap()
        };
        (rt, op)
    }

    #[test]
    fn test_remote_writer_buffers_and_uploads() {
        let (_rt, op) = mem_op();
        let op2 = op.clone();
        let mut w = RemoteWriter::new(op, "test/out.hash".to_string());
        writeln!(w, "blake3  abc123  /path/to/file.bin").unwrap();
        w.finish().unwrap();
        let bytes = op2.read("test/out.hash").unwrap();
        let text = String::from_utf8(bytes.to_bytes().to_vec()).unwrap();
        assert!(text.contains("blake3"));
    }

    #[test]
    fn test_remote_writer_empty_finish_succeeds() {
        let (_rt, op) = mem_op();
        let w = RemoteWriter::new(op, "test/empty.hash".to_string());
        // empty finish should not error
        w.finish().unwrap();
    }

    #[test]
    fn test_remote_writer_drop_uploads() {
        let (_rt, op) = mem_op();
        let op2 = op.clone();
        {
            let mut w = RemoteWriter::new(op, "test/drop.hash".to_string());
            writeln!(w, "sha256  deadbeef  /evidence/file.bin").unwrap();
            // Drop here triggers upload
        }
        // Verify it was uploaded
        let bytes = op2.read("test/drop.hash").unwrap();
        let text = String::from_utf8(bytes.to_bytes().to_vec()).unwrap();
        assert!(text.contains("sha256"));
    }

    #[test]
    fn test_output_writer_local_path_unchanged() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("out.hash");
        let mut w = blazehash::output::output_writer(Some(path.as_path())).unwrap();
        writeln!(w, "test line").unwrap();
        drop(w);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("test line"));
    }
}

// This test runs without --features remote to verify local path still works
#[test]
fn test_output_writer_stdout_when_none() {
    // Just verify it doesn't panic — can't capture stdout easily here
    let _w = blazehash::output::output_writer(None).unwrap();
}
