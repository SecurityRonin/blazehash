use std::str::FromStr;
use tlsh2::{TlshDefault, TlshDefaultBuilder};

/// Compute tlsh hash of `data`. Returns None if data is too short (minimum ~50 bytes)
/// or if the data lacks sufficient entropy for tlsh to produce a valid digest.
/// Returns the canonical digest string starting with "T1".
pub fn compute(data: &[u8]) -> Option<String> {
    let tlsh = TlshDefaultBuilder::build_from(data)?;
    let bytes = tlsh.hash();
    // hash() returns [u8; TLSH_STRING_LEN_REQ] — ASCII hex bytes
    Some(String::from_utf8(bytes.to_vec()).unwrap_or_default())
}

/// Convert tlsh distance to 0–100 similarity score.
/// distance 0 → 100, distance 300 → 0, clamped at 0.
pub fn distance_to_similarity(dist: i32) -> u32 {
    if dist <= 0 {
        return 100;
    }
    let score = 100i32 - (dist / 3);
    score.max(0) as u32
}

/// Compute similarity (0–100) between two tlsh digest strings.
/// Returns 0 if either hash is invalid or cannot be parsed.
pub fn similarity(h1: &str, h2: &str) -> u32 {
    let Ok(t1) = TlshDefault::from_str(h1) else {
        return 0;
    };
    let Ok(t2) = TlshDefault::from_str(h2) else {
        return 0;
    };
    let dist = t1.diff(&t2, true);
    distance_to_similarity(dist)
}
