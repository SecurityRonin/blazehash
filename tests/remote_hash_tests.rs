#[cfg(feature = "remote")]
mod remote_hash_tests {
    use opendal::{blocking, services, Operator};

    #[test]
    fn test_hash_remote_walk_module_exists() {
        // Verify the remote::walk module compiles by calling it with a sink
        use blazehash::algorithm::Algorithm;
        use blazehash::remote::walk::hash_remote_prefix;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let async_op = Operator::new(services::Memory::default()).unwrap().finish();
        let op = opendal::blocking::Operator::new(async_op).unwrap();
        let mut sink = Vec::<u8>::new();
        let _ = hash_remote_prefix(&op, "empty/", &[Algorithm::Blake3], &mut sink);
    }

    #[test]
    fn test_hash_remote_prefix_hashes_objects() {
        use blazehash::algorithm::Algorithm;
        use blazehash::remote::walk::hash_remote_prefix;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let async_op = Operator::new(services::Memory::default()).unwrap().finish();
        let op = blocking::Operator::new(async_op).unwrap();

        // Seed 3 objects
        op.write("evidence/file1.bin", b"content1".to_vec())
            .unwrap();
        op.write("evidence/file2.bin", b"content2".to_vec())
            .unwrap();
        op.write("evidence/file3.bin", b"content3".to_vec())
            .unwrap();

        let mut out = Vec::new();
        let count = hash_remote_prefix(&op, "evidence/", &[Algorithm::Blake3], &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();

        assert_eq!(count, 3, "should hash 3 objects");
        assert!(text.contains("evidence/file1.bin"), "file1 in output");
        assert!(text.contains("evidence/file2.bin"), "file2 in output");
        assert!(text.contains("evidence/file3.bin"), "file3 in output");
    }

    #[test]
    fn test_hash_remote_prefix_correct_hash() {
        use blazehash::algorithm::{hash_bytes, Algorithm};
        use blazehash::remote::walk::hash_remote_prefix;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let async_op = Operator::new(services::Memory::default()).unwrap().finish();
        let op = blocking::Operator::new(async_op).unwrap();

        let content = b"known content for hashing";
        op.write("test/known.bin", content.to_vec()).unwrap();

        let expected_hash = hash_bytes(Algorithm::Blake3, content);

        let mut out = Vec::new();
        hash_remote_prefix(&op, "test/", &[Algorithm::Blake3], &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(
            text.contains(&expected_hash),
            "correct BLAKE3 hash in output: expected {expected_hash}"
        );
    }

    #[test]
    fn test_hash_remote_single_object_count() {
        use blazehash::algorithm::Algorithm;
        use blazehash::remote::walk::hash_remote_prefix;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let async_op = Operator::new(services::Memory::default()).unwrap().finish();
        let op = blocking::Operator::new(async_op).unwrap();

        op.write("single/file.bin", b"data".to_vec()).unwrap();

        let mut out = Vec::new();
        let count = hash_remote_prefix(&op, "single/", &[Algorithm::Sha256], &mut out).unwrap();
        assert_eq!(count, 1);
    }
}

// Always-compiled: verify is_remote_uri handles edge cases
#[test]
fn test_is_remote_uri_with_trailing_slash() {
    assert!(blazehash::remote::is_remote_uri("s3://bucket/prefix/"));
    assert!(blazehash::remote::is_remote_uri("mem://store/"));
}
