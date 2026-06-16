const ROLLING_WINDOW: usize = 7;
const MIN_BLOCK_SIZE: u32 = 3;
const SPAMSUM_LENGTH: usize = 64;
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const FNV_PRIME: u32 = 16_777_619;
const FNV_INIT: u32 = 0x2802_1967;

struct RollingState {
    window: [u8; ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl RollingState {
    fn new() -> Self {
        Self {
            window: [0u8; ROLLING_WINDOW],
            h1: 0,
            h2: 0,
            h3: 0,
            n: 0,
        }
    }

    fn update(&mut self, c: u8) {
        self.h2 = self
            .h2
            .wrapping_sub(self.h1)
            .wrapping_add((ROLLING_WINDOW as u32).wrapping_mul(u32::from(c)));
        self.h1 = self
            .h1
            .wrapping_add(u32::from(c))
            .wrapping_sub(u32::from(self.window[self.n % ROLLING_WINDOW]));
        self.window[self.n % ROLLING_WINDOW] = c;
        self.n += 1;
        self.h3 = self.h3.rotate_left(5) ^ u32::from(c);
    }

    fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

fn choose_block_size(data_len: usize) -> u32 {
    let mut bs = MIN_BLOCK_SIZE;
    while bs as usize * SPAMSUM_LENGTH < data_len {
        bs *= 2;
    }
    bs
}

/// Compute ssdeep (CTPH) hash of `data`. Returns `"bs:hash1:hash2"`.
pub fn compute(data: &[u8]) -> String {
    let bs = choose_block_size(data.len());
    let (hash1, hash2) = compute_with_bs(data, bs);
    format!("{bs}:{hash1}:{hash2}")
}

fn compute_with_bs(data: &[u8], bs: u32) -> (String, String) {
    let mut roll = RollingState::new();
    let mut fnv1 = FNV_INIT;
    let mut fnv2 = FNV_INIT;
    let mut hash1 = Vec::with_capacity(SPAMSUM_LENGTH);
    let mut hash2 = Vec::with_capacity(SPAMSUM_LENGTH / 2);

    for &c in data {
        fnv1 = fnv1.wrapping_mul(FNV_PRIME) ^ u32::from(c);
        fnv2 = fnv2.wrapping_mul(FNV_PRIME) ^ u32::from(c);
        roll.update(c);
        let r = roll.sum();
        if r % bs == bs - 1 {
            if hash1.len() < SPAMSUM_LENGTH - 1 {
                hash1.push(B64[(fnv1 % 64) as usize]);
            }
            fnv1 = FNV_INIT;
        }
        if bs >= 2 && r % (bs / 2) == (bs / 2) - 1 {
            if hash2.len() < SPAMSUM_LENGTH / 2 - 1 {
                hash2.push(B64[(fnv2 % 64) as usize]);
            }
            fnv2 = FNV_INIT;
        }
    }

    // Append final FNV chars
    hash1.push(B64[(fnv1 % 64) as usize]);
    hash2.push(B64[(fnv2 % 64) as usize]);

    // Every byte pushed onto hash1/hash2 comes from the ASCII `B64` table, so the
    // vectors are valid UTF-8 by construction; `from_utf8_lossy` is exact here and
    // keeps the path panic-free if that invariant is ever broken.
    (
        String::from_utf8_lossy(&hash1).into_owned(),
        String::from_utf8_lossy(&hash2).into_owned(),
    )
}

/// Parse block size from a ssdeep hash string. Returns None on malformed input.
pub fn block_size(hash: &str) -> Option<u32> {
    hash.split(':').next()?.parse().ok()
}

/// Edit distance (Levenshtein) between two byte slices, capped at `cap`.
fn edit_distance(a: &[u8], b: &[u8], cap: usize) -> usize {
    if a == b {
        return 0;
    }
    let n = a.len();
    let m = b.len();
    if n == 0 {
        return m.min(cap);
    }
    if m == 0 {
        return n.min(cap);
    }

    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];

    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            curr[j] = if a[i - 1] == b[j - 1] {
                prev[j - 1]
            } else {
                1 + prev[j - 1].min(prev[j]).min(curr[j - 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
        // `prev` always has m+1 >= 1 entries here (m == 0 returns early above), so
        // `min()` is `Some`; `unwrap_or(0)` keeps the early-out panic-free.
        if prev.iter().min().copied().unwrap_or(0) >= cap {
            return cap;
        }
    }
    prev[m].min(cap)
}

/// Compute similarity (0-100) between two ssdeep hash strings.
/// Returns 0 for incompatible block sizes or malformed input.
pub fn similarity(h1: &str, h2: &str) -> u32 {
    let p1: Vec<&str> = h1.splitn(3, ':').collect();
    let p2: Vec<&str> = h2.splitn(3, ':').collect();
    if p1.len() < 3 || p2.len() < 3 {
        return 0;
    }

    let bs1: u32 = match p1[0].parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let bs2: u32 = match p2[0].parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if bs1 == bs2 {
        score_pair(p1[1].as_bytes(), p2[1].as_bytes())
            .max(score_pair(p1[2].as_bytes(), p2[2].as_bytes()))
    } else if bs1 == bs2 * 2 {
        score_pair(p1[1].as_bytes(), p2[2].as_bytes())
    } else if bs2 == bs1 * 2 {
        score_pair(p1[2].as_bytes(), p2[1].as_bytes())
    } else {
        0
    }
}

fn score_pair(a: &[u8], b: &[u8]) -> u32 {
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let len = a.len().max(b.len());
    let dist = edit_distance(a, b, len);
    100u32.saturating_sub((dist * 100 / len) as u32)
}

use std::collections::HashMap;
use std::path::PathBuf;

/// Index of ssdeep hashes by block size for fast candidate lookup.
/// Only manifest entries with same/adjacent block sizes can match (CTPH property).
pub struct SsdeepIndex {
    inner: HashMap<u32, Vec<(String, PathBuf)>>,
}

impl Default for SsdeepIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl SsdeepIndex {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Insert a ssdeep hash string and its associated path.
    pub fn insert(&mut self, hash: &str, path: PathBuf) {
        if let Some(bs) = block_size(hash) {
            self.inner
                .entry(bs)
                .or_default()
                .push((hash.to_string(), path));
        }
    }

    /// Return all candidates compatible with `query_hash` (same bs, or ×2, or ÷2).
    pub fn candidates(&self, query_hash: &str) -> Vec<&(String, PathBuf)> {
        let Some(bs) = block_size(query_hash) else {
            return vec![];
        };
        let mut results = Vec::new();
        for candidate_bs in [bs / 2, bs, bs * 2] {
            if candidate_bs == 0 {
                continue;
            }
            if let Some(entries) = self.inner.get(&candidate_bs) {
                results.extend(entries.iter());
            }
        }
        results
    }
}
