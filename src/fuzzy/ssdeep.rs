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
        self.h3 = self.h3.rotate_left(5) ^ (c as u32);
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

    (
        String::from_utf8(hash1).unwrap(),
        String::from_utf8(hash2).unwrap(),
    )
}

/// Parse block size from a ssdeep hash string. Returns None on malformed input.
pub fn block_size(hash: &str) -> Option<u32> {
    hash.splitn(2, ':').next()?.parse().ok()
}
