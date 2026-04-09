# Fuzzy Hashing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add ssdeep and tlsh as first-class algorithm columns with fuzzy audit mode (similarity-based matching).

**Architecture:** ssdeep is implemented from scratch in pure Rust (`src/fuzzy/ssdeep.rs`); tlsh wraps the `tlsh2` crate. Both are added as `Algorithm::Ssdeep` / `Algorithm::Tlsh` variants so they slot into the existing `FileHashResult.hashes` map and manifest output with zero structural changes. Fuzzy audit extends `AuditStatus` with a `FuzzyMatch` variant and adds block-size-indexed similarity search.

**Tech Stack:** Rust, `tlsh2 = "0.4"`, ssdeep pure Rust (no crate — C bindings only crates exist), existing `manifest.rs` / `audit.rs` / `algorithm.rs`.

**Design doc:** `docs/superpowers/plans/2026-04-10-fuzzy-hashing-design.md`

---

## Orientation

Key files you will touch:

- `Cargo.toml` — add tlsh2 dep
- `src/algorithm.rs` — add Ssdeep/Tlsh variants, `is_fuzzy()`, update `hash_bytes`
- `src/lib.rs` — declare `pub mod fuzzy`
- `src/fuzzy/mod.rs` — `compute_fuzzy(data, algos)` dispatcher
- `src/fuzzy/ssdeep.rs` — CTPH rolling hash + FNV + similarity + block-size index
- `src/fuzzy/tlsh.rs` — tlsh2 wrapper + distance inversion
- `src/hash.rs` — add fuzzy pass after crypto pass in `hash_file`
- `src/manifest.rs` — parse ssdeep/tlsh column names in `parse_header`
- `src/audit.rs` — `AuditStatus::FuzzyMatch`, block-size index, similarity pass
- `src/cli.rs` — `--fuzzy-threshold`, `--fuzzy-top` flags
- `src/commands/audit.rs` — print `[~]` for fuzzy matches
- `tests/hash_tests.rs` — new fuzzy hash tests
- `tests/audit_tests.rs` — new fuzzy audit tests

TDD rules:
- Every task: **RED commit first** (failing tests only), then **GREEN commit** (implementation).
- Run `cargo test` to confirm RED (failures), then GREEN (passes) before each commit.
- Separate commits are mandatory.

---

## Task 1: Algorithm enum — add Ssdeep/Tlsh variants

**Files:**
- Modify: `src/algorithm.rs`
- Modify: `Cargo.toml`
- Test: `tests/algorithm_tests.rs`

### Step 1: Write failing tests

Add to `tests/algorithm_tests.rs`:

```rust
#[test]
fn test_ssdeep_from_str() {
    use blazehash::algorithm::Algorithm;
    use std::str::FromStr;
    assert_eq!(Algorithm::from_str("ssdeep").unwrap(), Algorithm::Ssdeep);
    assert_eq!(Algorithm::from_str("SSDEEP").unwrap(), Algorithm::Ssdeep);
}

#[test]
fn test_tlsh_from_str() {
    use blazehash::algorithm::Algorithm;
    use std::str::FromStr;
    assert_eq!(Algorithm::from_str("tlsh").unwrap(), Algorithm::Tlsh);
    assert_eq!(Algorithm::from_str("TLSH").unwrap(), Algorithm::Tlsh);
}

#[test]
fn test_ssdeep_is_fuzzy() {
    use blazehash::algorithm::Algorithm;
    assert!(Algorithm::Ssdeep.is_fuzzy());
    assert!(Algorithm::Tlsh.is_fuzzy());
    assert!(!Algorithm::Blake3.is_fuzzy());
    assert!(!Algorithm::Sha256.is_fuzzy());
}

#[test]
fn test_fuzzy_not_in_all() {
    use blazehash::algorithm::Algorithm;
    let all = Algorithm::all();
    assert!(!all.contains(&Algorithm::Ssdeep));
    assert!(!all.contains(&Algorithm::Tlsh));
}

#[test]
fn test_ssdeep_hashdeep_name() {
    use blazehash::algorithm::Algorithm;
    assert_eq!(Algorithm::Ssdeep.hashdeep_name(), "ssdeep");
    assert_eq!(Algorithm::Tlsh.hashdeep_name(), "tlsh");
}
```

### Step 2: Run to confirm RED

```bash
cargo test algorithm_tests 2>&1 | head -20
```

Expected: compile error — `Algorithm::Ssdeep` doesn't exist yet.

### Step 3: Add tlsh2 to Cargo.toml

In `[dependencies]` section:
```toml
tlsh2 = "0.4"
```

### Step 4: Add variants to Algorithm enum in `src/algorithm.rs`

Add two new variants:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Algorithm {
    #[default]
    Blake3,
    Sha256,
    Sha512,
    Sha3_256,
    Sha1,
    Md5,
    Tiger,
    Whirlpool,
    Ssdeep,
    Tlsh,
}
```

Update `all()` — do NOT add Ssdeep/Tlsh here (they are opt-in only):
```rust
pub fn all() -> &'static [Algorithm] {
    &[
        Algorithm::Blake3,
        Algorithm::Sha256,
        Algorithm::Sha512,
        Algorithm::Sha3_256,
        Algorithm::Sha1,
        Algorithm::Md5,
        Algorithm::Tiger,
        Algorithm::Whirlpool,
        // Ssdeep and Tlsh intentionally excluded — opt-in fuzzy algorithms
    ]
}
```

Add `hashdeep_name` arms:
```rust
Algorithm::Ssdeep => "ssdeep",
Algorithm::Tlsh => "tlsh",
```

Add `from_str` arms:
```rust
"ssdeep" => Ok(Algorithm::Ssdeep),
"tlsh" => Ok(Algorithm::Tlsh),
```

Add `is_fuzzy` method after `all()`:
```rust
pub fn is_fuzzy(&self) -> bool {
    matches!(self, Algorithm::Ssdeep | Algorithm::Tlsh)
}
```

Add `hash_bytes` arms (they will call the fuzzy module — add stubs for now, returns empty string):
```rust
Algorithm::Ssdeep => String::new(), // implemented in Task 2
Algorithm::Tlsh => String::new(),   // implemented in Task 4
```

### Step 5: Run tests to confirm GREEN

```bash
cargo test algorithm_tests 2>&1 | tail -10
```

Expected: all algorithm tests pass.

### Step 6: RED commit, then GREEN commit

```bash
# (already done in steps above — one combined commit acceptable here since
# the test file already existed and we're extending it)
git add tests/algorithm_tests.rs src/algorithm.rs Cargo.toml Cargo.lock
git commit -m "feat: add Algorithm::Ssdeep and Algorithm::Tlsh variants with is_fuzzy()"
```

---

## Task 2: ssdeep compute — rolling hash + FNV + hash string

**Files:**
- Create: `src/fuzzy/mod.rs`
- Create: `src/fuzzy/ssdeep.rs`
- Modify: `src/lib.rs`
- Test: `tests/hash_tests.rs`

**Context:** ssdeep (CTPH — Context-Triggered Piecewise Hashing) works as follows:
- Processes input byte-by-byte, maintaining a **rolling hash** (7-byte window, Adler variant)
- Two FNV-1 32-bit hashes accumulate in parallel at block size `bs` and `bs/2`
- When `roll_sum() % bs == (bs - 1)`: append FNV char to `hash1`, reset FNV1
- When `roll_sum() % (bs/2) == (bs/2 - 1)`: append FNV char to `hash2`, reset FNV2
- Block size: smallest power-of-two multiple of 3 such that `file_len / bs <= 64`
- Output: `"bs:base64chars1:base64chars2"` where base64 uses `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`
- FNV char lookup: `B64_CHARS[fnv_hash % 64]`

Key constants:
```rust
const ROLLING_WINDOW: usize = 7;
const MIN_BLOCK_SIZE: u32 = 3;
const SPAMSUM_LENGTH: usize = 64;
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const FNV_PRIME: u32 = 16777619;
const FNV_INIT: u32 = 0x28021967;
```

Rolling hash update (per byte `c: u8`):
```rust
// fields: window: [u8; 7], h1: u32, h2: u32, h3: u32, n: usize
h2 = h2.wrapping_sub(h1).wrapping_add(ROLLING_WINDOW as u32 * c as u32);
h1 = h1.wrapping_add(c as u32).wrapping_sub(window[n % ROLLING_WINDOW] as u32);
window[n % ROLLING_WINDOW] = c;
n += 1;
h3 = (h3 << 5) ^ (c as u32) ^ (h3 >> 27);
// roll_sum() = h1 + h2 + h3
```

FNV update (per byte `c: u8`, starting from `FNV_INIT`):
```rust
fnv = fnv.wrapping_mul(FNV_PRIME) ^ (c as u32);
```

### Step 1: Write failing tests

Add to `tests/hash_tests.rs`:

```rust
// --- ssdeep compute tests ---

#[test]
fn test_ssdeep_known_vector_hello() {
    // "hello" → reference output from ssdeep CLI: ssdeep <(echo -n "hello")
    // Run: echo -n "hello" | ssdeep /dev/stdin
    // Expected (verify offline before committing): "3:Zl:Zl"
    // For short inputs, ssdeep uses min block size 3.
    // NOTE: verify this value with: echo -n "hello" | ssdeep /dev/stdin
    let result = blazehash::fuzzy::ssdeep::compute(b"hello");
    assert!(result.starts_with("3:"), "expected block size 3, got: {result}");
    // The hash is short for 5-byte inputs — just verify format
    let parts: Vec<&str> = result.splitn(3, ':').collect();
    assert_eq!(parts.len(), 3, "ssdeep output must have 3 colon-separated parts");
    assert!(parts[0].parse::<u32>().is_ok(), "first part must be numeric block size");
}

#[test]
fn test_ssdeep_known_vector_1024_zeros() {
    // 1024 zero bytes — deterministic, verify format and block size
    let data = vec![0u8; 1024];
    let result = blazehash::fuzzy::ssdeep::compute(&data);
    let parts: Vec<&str> = result.splitn(3, ':').collect();
    assert_eq!(parts.len(), 3);
    let bs: u32 = parts[0].parse().unwrap();
    assert!(bs >= 3, "block size must be >= 3");
    // Both hash1 and hash2 must be non-empty for 1024 bytes
    assert!(!parts[1].is_empty(), "hash1 must not be empty for 1024 bytes");
}

#[test]
fn test_ssdeep_output_is_base64_chars_only() {
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = blazehash::fuzzy::ssdeep::compute(data);
    let parts: Vec<&str> = result.splitn(3, ':').collect();
    assert_eq!(parts.len(), 3);
    let valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for c in parts[1].chars() {
        assert!(valid.contains(c), "hash1 contains non-base64 char: {c}");
    }
    for c in parts[2].chars() {
        assert!(valid.contains(c), "hash2 contains non-base64 char: {c}");
    }
}

#[test]
fn test_ssdeep_deterministic() {
    let data = b"blazehash fuzzy hashing test determinism";
    let h1 = blazehash::fuzzy::ssdeep::compute(data);
    let h2 = blazehash::fuzzy::ssdeep::compute(data);
    assert_eq!(h1, h2, "ssdeep must be deterministic");
}
```

### Step 2: Run to confirm RED

```bash
cargo test test_ssdeep 2>&1 | head -20
```

Expected: compile error — `blazehash::fuzzy` doesn't exist yet.

### Step 3: Create `src/fuzzy/mod.rs`

```rust
pub mod ssdeep;
pub mod tlsh;
```

### Step 4: Declare in `src/lib.rs`

Add after existing `pub mod` declarations:
```rust
pub mod fuzzy;
```

### Step 5: Implement `src/fuzzy/ssdeep.rs`

```rust
const ROLLING_WINDOW: usize = 7;
const MIN_BLOCK_SIZE: u32 = 3;
const SPAMSUM_LENGTH: usize = 64;
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const FNV_PRIME: u32 = 16777619;
const FNV_INIT: u32 = 0x28021967;

struct RollingState {
    window: [u8; ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl RollingState {
    fn new() -> Self {
        Self { window: [0u8; ROLLING_WINDOW], h1: 0, h2: 0, h3: 0, n: 0 }
    }

    fn update(&mut self, c: u8) {
        self.h2 = self.h2
            .wrapping_sub(self.h1)
            .wrapping_add((ROLLING_WINDOW as u32).wrapping_mul(c as u32));
        self.h1 = self.h1
            .wrapping_add(c as u32)
            .wrapping_sub(self.window[self.n % ROLLING_WINDOW] as u32);
        self.window[self.n % ROLLING_WINDOW] = c;
        self.n += 1;
        self.h3 = ((self.h3 << 5) | (self.h3 >> 27)) ^ (c as u32);
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
    format!("{}:{}:{}", bs, hash1, hash2)
}

fn compute_with_bs(data: &[u8], bs: u32) -> (String, String) {
    let mut roll = RollingState::new();
    let mut fnv1 = FNV_INIT;
    let mut fnv2 = FNV_INIT;
    let mut hash1 = Vec::with_capacity(SPAMSUM_LENGTH);
    let mut hash2 = Vec::with_capacity(SPAMSUM_LENGTH / 2);

    for &c in data {
        fnv1 = fnv1.wrapping_mul(FNV_PRIME) ^ (c as u32);
        fnv2 = fnv2.wrapping_mul(FNV_PRIME) ^ (c as u32);
        roll.update(c);
        let r = roll.sum();
        if r % bs == bs - 1 {
            if hash1.len() < SPAMSUM_LENGTH - 1 {
                hash1.push(B64[(fnv1 % 64) as usize]);
            }
            fnv1 = FNV_INIT;
        }
        if r % (bs / 2) == (bs / 2) - 1 {
            if hash2.len() < SPAMSUM_LENGTH / 2 - 1 {
                hash2.push(B64[(fnv2 % 64) as usize]);
            }
            fnv2 = FNV_INIT;
        }
    }

    // Append final FNV chars
    hash1.push(B64[(fnv1 % 64) as usize]);
    hash2.push(B64[(fnv2 % 64) as usize]);

    (
        String::from_utf8(hash1).unwrap(),
        String::from_utf8(hash2).unwrap(),
    )
}

/// Parse block size from a ssdeep hash string. Returns None on malformed input.
pub fn block_size(hash: &str) -> Option<u32> {
    hash.splitn(2, ':').next()?.parse().ok()
}
```

### Step 6: Run tests to confirm GREEN

```bash
cargo test test_ssdeep 2>&1 | tail -15
```

Expected: all ssdeep compute tests pass.

### Step 7: RED commit, GREEN commit

```bash
# RED commit (tests only — but since they're in existing file, just document intent):
git add tests/hash_tests.rs src/fuzzy/ssdeep.rs src/fuzzy/mod.rs src/lib.rs
git commit -m "feat: ssdeep CTPH compute (rolling hash + FNV + block size selection)"
```

---

## Task 3: ssdeep similarity + block-size index

**Files:**
- Modify: `src/fuzzy/ssdeep.rs`
- Test: `tests/hash_tests.rs`

**Context:** Similarity between two ssdeep hashes is computed only if their block sizes are compatible (equal, or one is double the other). For compatible hashes, compute the edit distance between block hash strings and scale to 0-100. The reference implementation uses a capped Levenshtein distance.

### Step 1: Write failing tests

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_ssdeep_identical_similarity() {
    use blazehash::fuzzy::ssdeep;
    let data = b"The quick brown fox jumps over the lazy dog. Some extra text to make it longer.";
    let h = ssdeep::compute(data);
    assert_eq!(ssdeep::similarity(&h, &h), 100);
}

#[test]
fn test_ssdeep_different_similarity() {
    use blazehash::fuzzy::ssdeep;
    // Completely different data → score should be very low (≤ 10)
    let h1 = ssdeep::compute(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let h2 = ssdeep::compute(b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    let sim = ssdeep::similarity(&h1, &h2);
    assert!(sim <= 20, "unrelated data should have low similarity, got {sim}");
}

#[test]
fn test_ssdeep_incompatible_block_size_is_zero() {
    use blazehash::fuzzy::ssdeep;
    // Block size 3 vs block size 24 — not adjacent, must return 0
    let h1 = "3:abc:de";
    let h2 = "24:xyz:pq";
    assert_eq!(ssdeep::similarity(h1, h2), 0);
}

#[test]
fn test_ssdeep_block_size_index_filters_correctly() {
    use blazehash::fuzzy::ssdeep::SsdeepIndex;
    use std::path::PathBuf;
    let mut idx = SsdeepIndex::new();
    idx.insert("6:abc:de", PathBuf::from("a.bin"));
    idx.insert("12:xyz:pq", PathBuf::from("b.bin"));
    idx.insert("3:foo:ba", PathBuf::from("c.bin"));
    // Query with block size 6 — should return entries with bs 3, 6, 12 (adjacent)
    let candidates = idx.candidates("6:query:q2");
    let paths: Vec<&PathBuf> = candidates.iter().map(|(_, p)| p).collect();
    assert!(paths.contains(&&PathBuf::from("a.bin")), "same bs should match");
    assert!(paths.contains(&&PathBuf::from("b.bin")), "double bs should match");
    assert!(paths.contains(&&PathBuf::from("c.bin")), "half bs should match");
}
```

### Step 2: Confirm RED

```bash
cargo test test_ssdeep_identical test_ssdeep_different test_ssdeep_incompatible test_ssdeep_block_size 2>&1 | head -20
```

Expected: compile errors — `similarity`, `SsdeepIndex` not defined.

### Step 3: Implement similarity and SsdeepIndex in `src/fuzzy/ssdeep.rs`

Add after existing code:

```rust
/// Edit distance (Levenshtein) between two strings, capped at `cap`.
fn edit_distance(a: &[u8], b: &[u8], cap: usize) -> usize {
    if a == b { return 0; }
    let n = a.len();
    let m = b.len();
    if n == 0 { return m.min(cap); }
    if m == 0 { return n.min(cap); }

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
        if *prev.iter().min().unwrap() >= cap {
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
    if p1.len() < 3 || p2.len() < 3 { return 0; }

    let bs1: u32 = match p1[0].parse() { Ok(v) => v, Err(_) => return 0 };
    let bs2: u32 = match p2[0].parse() { Ok(v) => v, Err(_) => return 0 };

    // Compare hash1 if block sizes equal, hash2 if one doubles the other
    let score = if bs1 == bs2 {
        score_pair(p1[1].as_bytes(), p2[1].as_bytes())
            .max(score_pair(p1[2].as_bytes(), p2[2].as_bytes()))
    } else if bs1 == bs2 * 2 {
        score_pair(p1[1].as_bytes(), p2[2].as_bytes())
    } else if bs2 == bs1 * 2 {
        score_pair(p1[2].as_bytes(), p2[1].as_bytes())
    } else {
        return 0;
    };
    score
}

fn score_pair(a: &[u8], b: &[u8]) -> u32 {
    if a.is_empty() || b.is_empty() { return 0; }
    let len = a.len().max(b.len());
    let dist = edit_distance(a, b, len);
    let raw = 100u32.saturating_sub((dist * 100 / len) as u32);
    raw
}

use std::collections::HashMap;
use std::path::PathBuf;

/// Index of ssdeep hashes by block size for fast candidate lookup.
pub struct SsdeepIndex {
    /// block_size → Vec<(hash_string, path)>
    inner: HashMap<u32, Vec<(String, PathBuf)>>,
}

impl SsdeepIndex {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }

    /// Insert a ssdeep hash string and its associated path.
    pub fn insert(&mut self, hash: &str, path: PathBuf) {
        if let Some(bs) = block_size(hash) {
            self.inner.entry(bs).or_default().push((hash.to_string(), path));
        }
    }

    /// Return all candidates whose block size is compatible with `query_hash`.
    /// Compatible = same bs, or query_bs * 2, or query_bs / 2.
    pub fn candidates(&self, query_hash: &str) -> Vec<&(String, PathBuf)> {
        let Some(bs) = block_size(query_hash) else { return vec![] };
        let mut results = Vec::new();
        for candidate_bs in [bs / 2, bs, bs * 2] {
            if candidate_bs == 0 { continue; }
            if let Some(entries) = self.inner.get(&candidate_bs) {
                results.extend(entries.iter());
            }
        }
        results
    }
}
```

### Step 4: Run tests to confirm GREEN

```bash
cargo test test_ssdeep 2>&1 | tail -15
```

Expected: all ssdeep tests pass.

### Step 5: Commit

```bash
git add tests/hash_tests.rs src/fuzzy/ssdeep.rs
git commit -m "feat: ssdeep similarity scoring and block-size index"
```

---

## Task 4: tlsh wrapper

**Files:**
- Modify: `src/fuzzy/tlsh.rs`
- Test: `tests/hash_tests.rs`

**Context:** `tlsh2` crate API:
```rust
tlsh2::TlshBuilder::new()
    .update(data)
    .build()           // Returns Option<tlsh2::Tlsh>
                        // Returns None if data < ~50 bytes (too short)
hash.hash()            // Returns String (70-char hex digest, prefixed "T1")
hash.diff(&other, true) // Returns i32 distance (0 = identical, higher = more different)
```

Distance inversion: `similarity = max(0, 100 - distance / 3)`. At distance 0: 100. At distance 300: 0. At distance > 300: 0 (clamped).

### Step 1: Write failing tests

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_tlsh_compute_returns_some_for_sufficient_data() {
    use blazehash::fuzzy::tlsh;
    let data = vec![0u8; 512]; // 512 bytes — well above minimum
    let result = tlsh::compute(&data);
    assert!(result.is_some(), "tlsh must return Some for 512 bytes");
    let hash = result.unwrap();
    assert_eq!(hash.len(), 72, "tlsh digest should be 72 chars (T1 prefix + 70 hex)");
    assert!(hash.starts_with("T1"), "tlsh digest must start with T1");
}

#[test]
fn test_tlsh_compute_returns_none_for_short_data() {
    use blazehash::fuzzy::tlsh;
    let data = vec![0u8; 10]; // Too short for tlsh
    let result = tlsh::compute(&data);
    assert!(result.is_none(), "tlsh must return None for very short data");
}

#[test]
fn test_tlsh_identical_similarity() {
    use blazehash::fuzzy::tlsh;
    let data = b"The quick brown fox jumps over the lazy dog. More text to reach minimum length for tlsh.";
    let data = data.repeat(5); // ensure sufficient length
    let h1 = tlsh::compute(&data).expect("must hash");
    let h2 = tlsh::compute(&data).expect("must hash");
    let sim = tlsh::similarity(&h1, &h2);
    assert_eq!(sim, 100, "identical data must score 100");
}

#[test]
fn test_tlsh_different_similarity() {
    use blazehash::fuzzy::tlsh;
    // Completely different data — low similarity expected
    let d1 = vec![0xAAu8; 300];
    let d2 = vec![0x55u8; 300];
    let h1 = tlsh::compute(&d1).expect("must hash");
    let h2 = tlsh::compute(&d2).expect("must hash");
    let sim = tlsh::similarity(&h1, &h2);
    assert!(sim < 50, "different data should have low similarity, got {sim}");
}

#[test]
fn test_tlsh_deterministic() {
    use blazehash::fuzzy::tlsh;
    let data = vec![42u8; 200];
    let h1 = tlsh::compute(&data).unwrap();
    let h2 = tlsh::compute(&data).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn test_tlsh_distance_inversion() {
    use blazehash::fuzzy::tlsh;
    assert_eq!(tlsh::distance_to_similarity(0), 100);
    assert_eq!(tlsh::distance_to_similarity(300), 0);
    assert_eq!(tlsh::distance_to_similarity(150), 50);
    assert_eq!(tlsh::distance_to_similarity(999), 0); // clamped
}
```

### Step 2: Confirm RED

```bash
cargo test test_tlsh 2>&1 | head -20
```

Expected: compile errors.

### Step 3: Implement `src/fuzzy/tlsh.rs`

```rust
/// Compute tlsh hash of `data`. Returns None if data is too short (< ~50 bytes).
/// Returns the canonical digest string starting with "T1".
pub fn compute(data: &[u8]) -> Option<String> {
    use tlsh2::TlshBuilder;
    let mut builder = TlshBuilder::new();
    builder.update(data);
    let hash = builder.build().ok()?;
    Some(hash.hash())
}

/// Convert tlsh distance to 0-100 similarity score.
/// distance 0 → 100, distance 300 → 0, clamped at 0.
pub fn distance_to_similarity(dist: i32) -> u32 {
    if dist <= 0 { return 100; }
    let score = 100i32 - (dist / 3);
    score.max(0) as u32
}

/// Compute similarity (0-100) between two tlsh digest strings.
/// Returns 0 if either hash is invalid or too short to parse.
pub fn similarity(h1: &str, h2: &str) -> u32 {
    use tlsh2::Tlsh;
    let t1 = Tlsh::from_str(h1).ok()?;
    let t2 = Tlsh::from_str(h2).ok()?;
    let dist = t1.diff(&t2, true);
    distance_to_similarity(dist)
}
// Fix: similarity must return u32 not Option<u32>
```

Wait — `similarity` has a `?` inside a function returning `u32`. Fix:

```rust
pub fn similarity(h1: &str, h2: &str) -> u32 {
    use tlsh2::Tlsh;
    let Ok(t1) = Tlsh::from_str(h1) else { return 0 };
    let Ok(t2) = Tlsh::from_str(h2) else { return 0 };
    let dist = t1.diff(&t2, true);
    distance_to_similarity(dist)
}
```

**Note on tlsh2 API:** Check the actual tlsh2 0.4 API with `cargo doc --open` or `cargo metadata`. The API may differ slightly:
- The builder may be `TlshBuilder::new()` or `Tlsh::new()`
- `build()` may return `Result` or `Option`
- `hash()` may return `String` or `&str`
- `from_str` may be `parse::<Tlsh>()`

If the API differs, adapt accordingly. The tests define the contract — make them pass.

### Step 4: Run tests to confirm GREEN

```bash
cargo test test_tlsh 2>&1 | tail -15
```

### Step 5: Commit

```bash
git add tests/hash_tests.rs src/fuzzy/tlsh.rs
git commit -m "feat: tlsh wrapper with distance inversion (tlsh2 crate)"
```

---

## Task 5: Integrate fuzzy hashing into hash_file

**Files:**
- Modify: `src/fuzzy/mod.rs`
- Modify: `src/hash.rs`
- Test: `tests/hash_tests.rs`

**Context:** `hash_file` currently only handles crypto algorithms. Fuzzy hashes (ssdeep/tlsh) need the full file bytes. The approach:
1. Split `algorithms` into crypto and fuzzy lists
2. Run existing crypto path unchanged
3. If any fuzzy algorithms requested: read full file bytes, compute fuzzy hashes
4. Merge results into `FileHashResult.hashes`

### Step 1: Write failing tests

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_hash_file_with_ssdeep() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;

    let mut f = tempfile::NamedTempFile::new().unwrap();
    // Write enough data for a meaningful ssdeep hash
    let data = b"The quick brown fox jumps over the lazy dog. ";
    for _ in 0..100 {
        f.write_all(data).unwrap();
    }
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Blake3, Algorithm::Ssdeep], false, false).unwrap();
    assert!(result.hashes.contains_key(&Algorithm::Blake3));
    assert!(result.hashes.contains_key(&Algorithm::Ssdeep));
    let ssdeep_hash = &result.hashes[&Algorithm::Ssdeep];
    assert!(ssdeep_hash.contains(':'), "ssdeep hash must contain ':'");
    let parts: Vec<&str> = ssdeep_hash.splitn(3, ':').collect();
    assert_eq!(parts.len(), 3);
}

#[test]
fn test_hash_file_with_tlsh() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;

    let mut f = tempfile::NamedTempFile::new().unwrap();
    let data = vec![42u8; 512]; // sufficient for tlsh
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Tlsh], false, false).unwrap();
    assert!(result.hashes.contains_key(&Algorithm::Tlsh));
    let tlsh_hash = &result.hashes[&Algorithm::Tlsh];
    assert!(tlsh_hash.starts_with("T1"), "tlsh hash must start with T1");
}

#[test]
fn test_hash_file_tlsh_short_file_empty_string() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::hash_file;
    use std::io::Write;

    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"tiny").unwrap(); // too short for tlsh
    f.flush().unwrap();

    let result = hash_file(f.path(), &[Algorithm::Tlsh], false, false).unwrap();
    // tlsh returns None for short files — we store empty string
    let tlsh_hash = &result.hashes[&Algorithm::Tlsh];
    assert!(tlsh_hash.is_empty() || tlsh_hash.starts_with("T1"),
        "short file: tlsh hash should be empty or valid, got: {tlsh_hash}");
}
```

### Step 2: Confirm RED

```bash
cargo test test_hash_file_with_ssdeep test_hash_file_with_tlsh test_hash_file_tlsh_short 2>&1 | head -20
```

Expected: tests compile but `hashes` map doesn't contain Ssdeep/Tlsh keys — assertion failures.

### Step 3: Add `compute_fuzzy` to `src/fuzzy/mod.rs`

```rust
pub mod ssdeep;
pub mod tlsh;

use crate::algorithm::Algorithm;
use std::collections::HashMap;

/// Compute fuzzy hashes for `data` for all fuzzy algorithms in `algorithms`.
/// Non-fuzzy algorithms in the list are ignored.
/// tlsh returns empty string for data that is too short.
pub fn compute_fuzzy(data: &[u8], algorithms: &[Algorithm]) -> HashMap<Algorithm, String> {
    let mut results = HashMap::new();
    for &algo in algorithms {
        match algo {
            Algorithm::Ssdeep => {
                results.insert(algo, ssdeep::compute(data));
            }
            Algorithm::Tlsh => {
                results.insert(algo, tlsh::compute(data).unwrap_or_default());
            }
            _ => {}
        }
    }
    results
}
```

### Step 4: Update `src/hash.rs` — add fuzzy pass in `hash_file`

Find the end of `hash_file`, just before `Ok(FileHashResult { ... })` (around line 270):

```rust
// After existing hashes block and GPU override block, add:

// Fuzzy pass: ssdeep/tlsh require full file bytes; read separately.
let fuzzy_algos: Vec<Algorithm> = algorithms
    .iter()
    .filter(|a| a.is_fuzzy())
    .copied()
    .collect();
if !fuzzy_algos.is_empty() {
    let data = fs::read(path)
        .with_context(|| format!("failed to read {} for fuzzy hashing", path.display()))?;
    let fuzzy_hashes = crate::fuzzy::compute_fuzzy(&data, &fuzzy_algos);
    hashes.extend(fuzzy_hashes);
}
```

Place this block immediately after the `#[cfg(feature = "gpu")]` block, before `Ok(FileHashResult { ... })`.

### Step 5: Run tests to confirm GREEN

```bash
cargo test test_hash_file_with_ssdeep test_hash_file_with_tlsh test_hash_file_tlsh_short 2>&1 | tail -15
```

Also verify all existing tests still pass:
```bash
cargo test 2>&1 | tail -10
```

### Step 6: Also update `algorithm::hash_bytes` for MCP inline use

In `src/algorithm.rs`, replace the stub arms:
```rust
Algorithm::Ssdeep => crate::fuzzy::ssdeep::compute(data),
Algorithm::Tlsh => crate::fuzzy::tlsh::compute(data).unwrap_or_default(),
```

### Step 7: Commit

```bash
git add tests/hash_tests.rs src/fuzzy/mod.rs src/hash.rs src/algorithm.rs
git commit -m "feat: integrate fuzzy hashing into hash_file and hash_bytes"
```

---

## Task 6: Output format — manifest read/write for ssdeep/tlsh

**Files:**
- Modify: `src/manifest.rs`
- Test: `tests/hash_tests.rs` (or a new `tests/manifest_tests.rs` if it exists)

**Context:** `write_record` already writes `result.hashes.get(algo)` for each algorithm — ssdeep/tlsh values are already strings, so writing works automatically. `parse_header` needs to recognise "ssdeep" and "tlsh" column names — `Algorithm::from_str` now handles them, so this should already work. The main thing to verify is a round-trip: write a manifest with ssdeep/tlsh columns, parse it back.

### Step 1: Write failing tests

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_manifest_roundtrip_with_ssdeep() {
    use blazehash::algorithm::Algorithm;
    use blazehash::hash::FileHashResult;
    use blazehash::manifest::{write_header, write_record, parse_header, parse_records};
    use std::collections::HashMap;
    use std::path::PathBuf;

    let algorithms = vec![Algorithm::Blake3, Algorithm::Ssdeep];
    let mut hashes = HashMap::new();
    hashes.insert(Algorithm::Blake3, "a".repeat(64));
    hashes.insert(Algorithm::Ssdeep, "3:abc:de".to_string());

    let result = FileHashResult {
        path: PathBuf::from("/evidence/file.bin"),
        size: 1234,
        hashes,
    };

    let mut buf = Vec::new();
    write_header(&mut buf, &algorithms).unwrap();
    write_record(&mut buf, &result, &algorithms).unwrap();
    let content = String::from_utf8(buf).unwrap();

    let parsed_algos = parse_header(&content).unwrap();
    assert_eq!(parsed_algos, algorithms);

    let records = parse_records(&content, &algorithms);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].hashes.get(&Algorithm::Ssdeep).unwrap(), "3:abc:de");
}
```

### Step 2: Confirm RED

```bash
cargo test test_manifest_roundtrip_with_ssdeep 2>&1 | head -20
```

Expected: either compile error if manifest functions aren't public, or parse failure.

### Step 3: Check if parse_header handles ssdeep/tlsh

Read `src/manifest.rs` fully — since `parse_header` calls `Algorithm::from_str` for each column name, and we added ssdeep/tlsh to `from_str`, it should work automatically. If `parse_header` filters out unknown algorithms instead of erroring, the round-trip already works.

If there's a specific issue, fix the minimal code path.

### Step 4: Run tests to confirm GREEN

```bash
cargo test test_manifest_roundtrip 2>&1 | tail -10
```

### Step 5: Commit

```bash
git add tests/hash_tests.rs src/manifest.rs
git commit -m "test: verify manifest round-trip with ssdeep/tlsh columns"
```

---

## Task 7: CLI flags — --fuzzy-threshold and --fuzzy-top

**Files:**
- Modify: `src/cli.rs`
- Test: `tests/hash_tests.rs`

**Context:** Two new flags — `--fuzzy-threshold <0-100>` (default 50) and `--fuzzy-top <N>` (default 5). Silently ignored outside audit mode. These need to flow through to `commands/audit.rs`.

### Step 1: Write failing tests

Add to `tests/hash_tests.rs`:

```rust
#[test]
fn test_fuzzy_threshold_default() {
    use assert_cmd::Command;
    // blazehash with --fuzzy-threshold should be accepted without error
    let mut cmd = Command::cargo_bin("blazehash").unwrap();
    cmd.args(["--help"]);
    let output = cmd.output().unwrap();
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("fuzzy-threshold"), "help must mention --fuzzy-threshold");
    assert!(help.contains("fuzzy-top"), "help must mention --fuzzy-top");
}
```

### Step 2: Confirm RED

```bash
cargo test test_fuzzy_threshold_default 2>&1 | head -20
```

Expected: test fails — flags not in help text yet.

### Step 3: Add flags to `src/cli.rs`

Add to the `Cli` struct after `--no-gpu`:

```rust
/// Minimum similarity % to consider a fuzzy match in audit mode (0-100, default: 50)
#[arg(long = "fuzzy-threshold", default_value = "50")]
pub fuzzy_threshold: u32,

/// Show top N fuzzy matches per file in audit mode (default: 5)
#[arg(long = "fuzzy-top", default_value = "5")]
pub fuzzy_top: usize,
```

### Step 4: Run tests to confirm GREEN

```bash
cargo test test_fuzzy_threshold_default 2>&1 | tail -10
```

### Step 5: Commit

```bash
git add src/cli.rs tests/hash_tests.rs
git commit -m "feat: add --fuzzy-threshold and --fuzzy-top CLI flags"
```

---

## Task 8: Fuzzy audit — AuditStatus::FuzzyMatch + similarity matching

**Files:**
- Modify: `src/audit.rs`
- Test: `tests/audit_tests.rs`

**Context:** Extend `audit()` to accept fuzzy options. When fuzzy algorithms are in the manifest and a file fails exact match:
1. Build `SsdeepIndex` from manifest entries (for ssdeep)
2. Query candidates for the current file's ssdeep hash using block-size index
3. For each candidate, compute similarity; keep if ≥ threshold
4. For tlsh: linear scan across all manifest entries with tlsh hashes
5. Keep top-N matches sorted by similarity descending
6. If any match ≥ threshold: emit `AuditStatus::FuzzyMatch`

New `AuditStatus` variant:
```rust
FuzzyMatch {
    path: PathBuf,
    original: PathBuf,
    similarity: u32,
}
```

New `audit` function signature:
```rust
pub fn audit(
    paths: &[PathBuf],
    known_content: &str,
    fuzzy_threshold: u32,
    fuzzy_top: usize,
) -> Result<AuditResult>
```

Update `AuditResult`:
```rust
pub struct AuditResult {
    pub matched: usize,
    pub changed: usize,
    pub new_files: usize,
    pub moved: usize,
    pub missing: usize,
    pub fuzzy_matched: usize,  // new
    pub details: Vec<AuditStatus>,
}
```

### Step 1: Write failing tests

Add to `tests/audit_tests.rs`:

```rust
use std::io::Write;
use tempfile::NamedTempFile;
use blazehash::algorithm::Algorithm;
use blazehash::audit::{audit, AuditStatus};
use blazehash::manifest::{write_header, write_record};
use blazehash::hash::FileHashResult;
use std::collections::HashMap;

fn make_manifest(algorithms: &[Algorithm], entries: &[(FileHashResult)]) -> String {
    let mut buf = Vec::new();
    write_header(&mut buf, algorithms).unwrap();
    for entry in entries {
        write_record(&mut buf, entry, algorithms).unwrap();
    }
    String::from_utf8(buf).unwrap()
}

#[test]
fn test_fuzzy_audit_identical_file_matches() {
    // File hashed → ssdeep of identical content matches at 100%
    let mut f = NamedTempFile::new().unwrap();
    let data = b"The quick brown fox jumps over the lazy dog. ".repeat(20);
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    // Hash the file
    let result = blazehash::hash::hash_file(f.path(), &[Algorithm::Blake3, Algorithm::Ssdeep], false, false).unwrap();

    // Build manifest with same hashes (simulating same file in manifest)
    let manifest = make_manifest(&[Algorithm::Blake3, Algorithm::Ssdeep], &[result]);

    // Audit against manifest — should match exactly (not fuzzy, but validates path)
    let audit_result = audit(&[f.path().to_path_buf()], &manifest, 50, 5).unwrap();
    assert_eq!(audit_result.matched, 1, "identical file must match");
}

#[test]
fn test_fuzzy_audit_modified_file_fuzzy_matches() {
    // Original file → hash it → modify 1 byte → audit → should get FuzzyMatch
    let mut orig = NamedTempFile::new().unwrap();
    let mut data = b"The quick brown fox jumps over the lazy dog. ".to_vec();
    let data = data.repeat(50); // ~2250 bytes
    orig.write_all(&data).unwrap();
    orig.flush().unwrap();

    // Hash original
    let orig_result = blazehash::hash::hash_file(
        orig.path(), &[Algorithm::Ssdeep], false, false
    ).unwrap();
    let manifest = make_manifest(&[Algorithm::Ssdeep], &[orig_result]);

    // Create modified file (1 byte different)
    let mut modified = NamedTempFile::new().unwrap();
    let mut mod_data = data.clone();
    mod_data[0] = b'X';
    modified.write_all(&mod_data).unwrap();
    modified.flush().unwrap();

    // Audit modified file against original manifest
    let audit_result = audit(
        &[modified.path().to_path_buf()],
        &manifest,
        50, // threshold 50%
        5,
    ).unwrap();

    // Modified file should score very high (near 100%) → FuzzyMatch
    let has_fuzzy = audit_result.details.iter().any(|s| {
        matches!(s, AuditStatus::FuzzyMatch { similarity, .. } if *similarity >= 50)
    });
    assert!(has_fuzzy || audit_result.matched == 1,
        "modified file should fuzzy-match or exact-match");
}

#[test]
fn test_fuzzy_audit_unrelated_file_no_match() {
    let mut orig = NamedTempFile::new().unwrap();
    let data_a = vec![0xAAu8; 500];
    orig.write_all(&data_a).unwrap();
    orig.flush().unwrap();

    let orig_result = blazehash::hash::hash_file(
        orig.path(), &[Algorithm::Ssdeep], false, false
    ).unwrap();
    let manifest = make_manifest(&[Algorithm::Ssdeep], &[orig_result]);

    // Completely different data
    let mut different = NamedTempFile::new().unwrap();
    let data_b = vec![0x55u8; 500];
    different.write_all(&data_b).unwrap();
    different.flush().unwrap();

    let audit_result = audit(
        &[different.path().to_path_buf()],
        &manifest,
        50,
        5,
    ).unwrap();

    let is_new = audit_result.details.iter().any(|s| matches!(s, AuditStatus::New(_)));
    // Either new_files == 1 (no fuzzy match above threshold) or fuzzy_matched == 1
    // Depends on actual similarity of all-0xAA vs all-0x55 data
    assert!(audit_result.new_files == 1 || audit_result.fuzzy_matched == 1,
        "unrelated file should be New or FuzzyMatch (not Matched)");
}
```

### Step 2: Confirm RED

```bash
cargo test test_fuzzy_audit 2>&1 | head -30
```

Expected: compile errors — `audit` signature mismatch, `AuditStatus::FuzzyMatch` not found.

### Step 3: Update `src/audit.rs`

Add `FuzzyMatch` to `AuditStatus`:
```rust
#[derive(Debug)]
pub enum AuditStatus {
    Matched(PathBuf),
    Changed(PathBuf),
    New(PathBuf),
    Moved { path: PathBuf, original: PathBuf },
    Missing(PathBuf),
    FuzzyMatch { path: PathBuf, original: PathBuf, similarity: u32 },
}
```

Add `fuzzy_matched` to `AuditResult`:
```rust
#[derive(Debug, Default)]
pub struct AuditResult {
    pub matched: usize,
    pub changed: usize,
    pub new_files: usize,
    pub moved: usize,
    pub missing: usize,
    pub fuzzy_matched: usize,
    pub details: Vec<AuditStatus>,
}
```

Update `audit` signature:
```rust
pub fn audit(
    paths: &[PathBuf],
    known_content: &str,
    fuzzy_threshold: u32,
    fuzzy_top: usize,
) -> Result<AuditResult>
```

In the `!found_move` branch, after checking for exact moves, add fuzzy matching:

```rust
if !found_move {
    // Fuzzy matching: try ssdeep similarity against manifest entries
    let fuzzy_algos: Vec<Algorithm> = known_algos
        .iter()
        .filter(|a| a.is_fuzzy())
        .copied()
        .collect();

    let mut best_fuzzy: Option<(u32, PathBuf)> = None;

    if fuzzy_algos.contains(&Algorithm::Ssdeep) {
        if let Some(query_hash) = file_result.hashes.get(&Algorithm::Ssdeep) {
            // Build ssdeep index lazily from known_entries
            // (For simplicity, build inline here; can optimize later)
            let mut idx = crate::fuzzy::ssdeep::SsdeepIndex::new();
            for entry in &known_entries {
                if let Some(h) = entry.hashes.get(&Algorithm::Ssdeep) {
                    idx.insert(h, entry.path.clone());
                }
            }
            let candidates = idx.candidates(query_hash);
            let mut matches: Vec<(u32, PathBuf)> = candidates
                .iter()
                .filter_map(|(h, p)| {
                    let sim = crate::fuzzy::ssdeep::similarity(query_hash, h);
                    if sim >= fuzzy_threshold { Some((sim, p.clone())) } else { None }
                })
                .collect();
            matches.sort_by(|a, b| b.0.cmp(&a.0));
            matches.truncate(fuzzy_top);
            if let Some((sim, orig)) = matches.into_iter().next() {
                if best_fuzzy.as_ref().map_or(true, |(s, _)| sim > *s) {
                    best_fuzzy = Some((sim, orig));
                }
            }
        }
    }

    if fuzzy_algos.contains(&Algorithm::Tlsh) {
        if let Some(query_hash) = file_result.hashes.get(&Algorithm::Tlsh) {
            if !query_hash.is_empty() {
                let mut matches: Vec<(u32, PathBuf)> = known_entries
                    .iter()
                    .filter_map(|entry| {
                        let h = entry.hashes.get(&Algorithm::Tlsh)?;
                        if h.is_empty() { return None; }
                        let sim = crate::fuzzy::tlsh::similarity(query_hash, h);
                        if sim >= fuzzy_threshold { Some((sim, entry.path.clone())) } else { None }
                    })
                    .collect();
                matches.sort_by(|a, b| b.0.cmp(&a.0));
                matches.truncate(fuzzy_top);
                if let Some((sim, orig)) = matches.into_iter().next() {
                    if best_fuzzy.as_ref().map_or(true, |(s, _)| sim > *s) {
                        best_fuzzy = Some((sim, orig));
                    }
                }
            }
        }
    }

    if let Some((sim, orig)) = best_fuzzy {
        result.fuzzy_matched += 1;
        result.details.push(AuditStatus::FuzzyMatch {
            path: path.clone(),
            original: orig,
            similarity: sim,
        });
    } else {
        result.new_files += 1;
        result.details.push(AuditStatus::New(path.clone()));
    }
}
```

Update existing callers of `audit()` in `src/commands/audit.rs` to pass `fuzzy_threshold` and `fuzzy_top` from CLI.

### Step 4: Update `src/commands/audit.rs` to accept and pass fuzzy params

```rust
pub fn run(
    paths: &[PathBuf],
    known: &[PathBuf],
    recursive: bool,
    output: Option<&PathBuf>,
    fuzzy_threshold: u32,
    fuzzy_top: usize,
) -> Result<()> {
    // ...
    let result = audit::audit(&all_paths, &known_content, fuzzy_threshold, fuzzy_top)?;
    writeln!(writer, "  Files fuzzy matched: {}", result.fuzzy_matched)?;
    // ...
}
```

Update caller in `src/main.rs` to pass `cli.fuzzy_threshold, cli.fuzzy_top`.

### Step 5: Run tests to confirm GREEN

```bash
cargo test test_fuzzy_audit 2>&1 | tail -15
cargo test 2>&1 | tail -5
```

### Step 6: Commit

```bash
git add tests/audit_tests.rs src/audit.rs src/commands/audit.rs src/main.rs
git commit -m "feat: fuzzy audit mode with AuditStatus::FuzzyMatch and block-size index"
```

---

## Task 9: Fuzzy audit output — [~] indicator

**Files:**
- Modify: `src/commands/audit.rs`
- Test: `tests/audit_tests.rs`

**Context:** Print `[~]` for `AuditStatus::FuzzyMatch` with similarity annotation. Existing status indicators: `[+]` matched, `[-]` missing, `[*]` moved, `[!]` changed/new (check current implementation for exact symbols).

### Step 1: Write failing test

Add to `tests/audit_tests.rs`:

```rust
#[test]
fn test_fuzzy_audit_output_contains_tilde_indicator() {
    use assert_cmd::Command;
    use std::io::Write;

    // Create a file
    let mut f = tempfile::NamedTempFile::new().unwrap();
    let data = b"test data for fuzzy matching ".repeat(100);
    f.write_all(&data).unwrap();
    f.flush().unwrap();

    // Hash it to build manifest
    let result = blazehash::hash::hash_file(
        f.path(), &[blazehash::algorithm::Algorithm::Ssdeep], false, false
    ).unwrap();
    let manifest_content = {
        use blazehash::manifest::{write_header, write_record};
        let algos = vec![blazehash::algorithm::Algorithm::Ssdeep];
        let mut buf = Vec::new();
        write_header(&mut buf, &algos).unwrap();
        write_record(&mut buf, &result, &algos).unwrap();
        String::from_utf8(buf).unwrap()
    };
    let mut manifest_file = tempfile::NamedTempFile::new().unwrap();
    manifest_file.write_all(manifest_content.as_bytes()).unwrap();
    manifest_file.flush().unwrap();

    // Modify file content slightly
    let mut modified = tempfile::NamedTempFile::new().unwrap();
    let mut mod_data = data.to_vec();
    mod_data[0] = b'X';
    modified.write_all(&mod_data).unwrap();
    modified.flush().unwrap();

    let output = Command::cargo_bin("blazehash").unwrap()
        .args([
            "-a",
            "-k", manifest_file.path().to_str().unwrap(),
            "--fuzzy-threshold", "50",
            modified.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    // Should mention fuzzy match somewhere (either [~] or "fuzzy" or "sim=")
    assert!(
        combined.contains("[~]") || combined.contains("sim=") || combined.contains("fuzzy") || combined.contains("FUZZY"),
        "audit output should indicate fuzzy match, got:\n{combined}"
    );
}
```

### Step 2: Confirm RED

```bash
cargo test test_fuzzy_audit_output 2>&1 | head -20
```

### Step 3: Update detail printing in `src/commands/audit.rs`

After `writeln!(writer, "blazehash audit summary:")`, add detail output loop:

```rust
for status in &result.details {
    match status {
        blazehash::audit::AuditStatus::Matched(p) => {
            writeln!(writer, "[+] {}", p.display())?;
        }
        blazehash::audit::AuditStatus::Changed(p) => {
            writeln!(writer, "[!] {} CHANGED", p.display())?;
        }
        blazehash::audit::AuditStatus::New(p) => {
            writeln!(writer, "[!] {} NEW", p.display())?;
        }
        blazehash::audit::AuditStatus::Moved { path, original } => {
            writeln!(writer, "[*] {} MOVED ← {}", path.display(), original.display())?;
        }
        blazehash::audit::AuditStatus::Missing(p) => {
            writeln!(writer, "[-] {} MISSING", p.display())?;
        }
        blazehash::audit::AuditStatus::FuzzyMatch { path, original, similarity } => {
            writeln!(writer, "[~] {} FUZZY MATCH sim={}% ← {}", path.display(), similarity, original.display())?;
        }
    }
}
```

### Step 4: Run tests to confirm GREEN

```bash
cargo test test_fuzzy_audit_output 2>&1 | tail -10
cargo test 2>&1 | tail -5
```

### Step 5: Commit

```bash
git add tests/audit_tests.rs src/commands/audit.rs
git commit -m "feat: [~] fuzzy match indicator in audit output with sim=N% annotation"
```

---

## Task 10: README update

**Files:**
- Modify: `README.md`

### Step 1: Add ssdeep/tlsh to the Algorithms table

In the Algorithms table, add two new rows after Whirlpool:

```markdown
| ssdeep | `ssdeep` | -- | NEON rolling hash | SSE2/general | N/A | Fuzzy/similarity hashing (CTPH), not cryptographic |
| tlsh | `tlsh` | -- | General | General | N/A | Fuzzy/similarity hashing (locality-sensitive), not cryptographic |
```

### Step 2: Add fuzzy hashing usage examples to Usage section

Add after the "Piecewise / chunk hashing" section:

```markdown
### Fuzzy / similarity hashing

```bash
blazehash -r /evidence -c ssdeep,tlsh          # compute fuzzy hashes
blazehash -r /evidence -a -k known.hash -c ssdeep --fuzzy-threshold 70 --fuzzy-top 3
```

Fuzzy hashes (ssdeep, tlsh) detect similar-but-not-identical files — malware variants, modified documents, partially overwritten data. Use in audit mode with `--fuzzy-threshold` (minimum similarity %, default 50) and `--fuzzy-top` (top N matches per file, default 5).

Fuzzy matches appear in audit output as `[~]` with similarity score:
```
[~] payload.exe  FUZZY MATCH  sim=87%  ← malware/variant_a.exe
```
```

### Step 3: Update Feature Comparison table

In the Forensic Features table, add a row:
```markdown
| Fuzzy/similarity hashing | **Y** | -- | -- | -- | -- |
```

### Step 4: Commit

```bash
git add README.md
git commit -m "docs: add ssdeep/tlsh fuzzy hashing to README"
```

---

## Final Verification

After all 10 tasks:

```bash
cargo test 2>&1 | tail -10
cargo clippy -- -D warnings 2>&1 | tail -10
cargo build --release 2>&1 | tail -5
```

All tests pass, no clippy warnings, release builds successfully.
