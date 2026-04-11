#[cfg(feature = "nsrl")]
mod nsrl_tests {
    use blazehash::nsrl::{NsrlLookup, NsrlResult};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_test_db(dir: &std::path::Path) -> PathBuf {
        use rusqlite::Connection;
        let db_path = dir.join("NSRL.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE FILE (SHA256 TEXT, MD5 TEXT, FileName TEXT, ProductCode INTEGER);
            INSERT INTO FILE VALUES ('aabbcc', 'ddeeff', 'notepad.exe', 1);
        ",
        )
        .unwrap();
        db_path
    }

    #[test]
    fn test_nsrl_sqlite_known_good() {
        let dir = tempdir().unwrap();
        let db = make_test_db(dir.path());
        let lookup = NsrlLookup::open(&db).unwrap();
        assert_eq!(lookup.lookup("aabbcc"), NsrlResult::KnownGood);
    }

    #[test]
    fn test_nsrl_sqlite_unknown() {
        let dir = tempdir().unwrap();
        let db = make_test_db(dir.path());
        let lookup = NsrlLookup::open(&db).unwrap();
        assert_eq!(lookup.lookup("deadbeef"), NsrlResult::Unknown);
    }

    #[test]
    fn test_nsrl_bloom_file_is_rejected() {
        // Bloom filters are probabilistic and can produce false positives,
        // silently suppressing evidence. They are not permitted for NSRL lookup.
        // Build a valid bloom file from the test DB, then verify it is rejected.
        let dir = tempdir().unwrap();
        let db = make_test_db(dir.path());
        let bloom_path = dir.path().join("nsrl.bloom");
        blazehash::nsrl::build_bloom(&db, &bloom_path, 0.001).unwrap();

        match NsrlLookup::open(&bloom_path) {
            Ok(_) => {
                panic!("expected error opening .bloom file, got Ok — bloom should be rejected")
            }
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                assert!(
                    msg.contains("bloom")
                        || msg.contains("not supported")
                        || msg.contains("sqlite"),
                    "error should mention bloom or sqlite, got: {msg}"
                );
            }
        }
    }
}
