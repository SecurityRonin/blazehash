#[cfg(feature = "nsrl")]
mod nsrl_tests {
    use blazehash::nsrl::{NsrlLookup, NsrlResult};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn make_test_db(dir: &std::path::Path) -> PathBuf {
        use rusqlite::Connection;
        let db_path = dir.join("NSRL.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("
            CREATE TABLE FILE (SHA256 TEXT, MD5 TEXT, FileName TEXT, ProductCode INTEGER);
            INSERT INTO FILE VALUES ('aabbcc', 'ddeeff', 'notepad.exe', 1);
        ").unwrap();
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
    fn test_nsrl_bloom_build_and_query() {
        let dir = tempdir().unwrap();
        let db = make_test_db(dir.path());
        let bloom_path = dir.path().join("nsrl.bloom");
        blazehash::nsrl::build_bloom(&db, &bloom_path, 0.001).unwrap();

        let lookup = NsrlLookup::open(&bloom_path).unwrap();
        assert_eq!(lookup.lookup("aabbcc"), NsrlResult::KnownGood);
    }
}
