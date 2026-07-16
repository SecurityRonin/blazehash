//! Newtype wrappers that implement `digest::Digest` for algorithms whose native
//! APIs don't satisfy the trait (XOFs, checksums).
//!
//! In `digest` 0.10, `Digest` is a blanket over `HashMarker + Update +
//! OutputSizeUser + FixedOutput + Default + Clone`.  Each wrapper here
//! implements those lower-level traits; `Digest::digest()`, `chain_update()`,
//! etc. come for free.

use digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Update};
use digest::typenum::{U4, U8, U16, U32, U64};

// ── SHAKE128 → 32 bytes ──────────────────────────────────────────────────────

/// SHAKE128 with a fixed 32-byte (256-bit) output.
///
/// NIST uses this exact truncation in SHAKE128 "hash mode" applications.
#[derive(Clone, Default)]
pub struct Shake128Fixed(sha3::Shake128);

impl HashMarker for Shake128Fixed {}

impl OutputSizeUser for Shake128Fixed {
    type OutputSize = U32;
}

impl Update for Shake128Fixed {
    fn update(&mut self, data: &[u8]) {
        sha3::digest::Update::update(&mut self.0, data);
    }
}

impl FixedOutput for Shake128Fixed {
    fn finalize_into(self, out: &mut Output<Self>) {
        use sha3::digest::{ExtendableOutput, XofReader};
        let mut reader = self.0.finalize_xof();
        reader.read(out.as_mut_slice());
    }
}

// ── SHAKE256 → 64 bytes ──────────────────────────────────────────────────────

/// SHAKE256 with a fixed 64-byte (512-bit) output.
#[derive(Clone, Default)]
pub struct Shake256Fixed(sha3::Shake256);

impl HashMarker for Shake256Fixed {}

impl OutputSizeUser for Shake256Fixed {
    type OutputSize = U64;
}

impl Update for Shake256Fixed {
    fn update(&mut self, data: &[u8]) {
        sha3::digest::Update::update(&mut self.0, data);
    }
}

impl FixedOutput for Shake256Fixed {
    fn finalize_into(self, out: &mut Output<Self>) {
        use sha3::digest::{ExtendableOutput, XofReader};
        let mut reader = self.0.finalize_xof();
        reader.read(out.as_mut_slice());
    }
}

// ── KangarooTwelve → 32 bytes ────────────────────────────────────────────────

/// KangarooTwelve (K12) with a fixed 32-byte output and empty customisation.
///
/// `tiny_keccak::KangarooTwelve` does not implement `Clone`, so this wrapper
/// buffers input bytes and hashes at finalization.
#[derive(Clone, Default)]
pub struct K12Fixed(Vec<u8>);

impl HashMarker for K12Fixed {}

impl OutputSizeUser for K12Fixed {
    type OutputSize = U32;
}

impl Update for K12Fixed {
    fn update(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
}

impl FixedOutput for K12Fixed {
    fn finalize_into(self, out: &mut Output<Self>) {
        use tiny_keccak::Hasher;
        let mut h = tiny_keccak::KangarooTwelve::new(b"");
        h.update(&self.0);
        h.finalize(out.as_mut_slice());
    }
}

// ── CRC32c → 4 bytes ─────────────────────────────────────────────────────────

/// CRC32C checksum with 4-byte big-endian output.
#[derive(Clone, Default)]
pub struct Crc32cDigest(Vec<u8>);

impl HashMarker for Crc32cDigest {}

impl OutputSizeUser for Crc32cDigest {
    type OutputSize = U4;
}

impl Update for Crc32cDigest {
    fn update(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
}

impl FixedOutput for Crc32cDigest {
    fn finalize_into(self, out: &mut Output<Self>) {
        out.copy_from_slice(&crc32c::crc32c(&self.0).to_be_bytes());
    }
}

// ── CRC64 → 8 bytes ──────────────────────────────────────────────────────────

/// CRC-64/ECMA-182 with 8-byte big-endian output.
#[derive(Clone, Default)]
pub struct Crc64Digest(Vec<u8>);

impl HashMarker for Crc64Digest {}

impl OutputSizeUser for Crc64Digest {
    type OutputSize = U8;
}

impl Update for Crc64Digest {
    fn update(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
}

impl FixedOutput for Crc64Digest {
    fn finalize_into(self, out: &mut Output<Self>) {
        let checksum = crc::Crc::<u64>::new(&crc::CRC_64_ECMA_182).checksum(&self.0);
        out.copy_from_slice(&checksum.to_be_bytes());
    }
}

// ── Adler32 → 4 bytes ────────────────────────────────────────────────────────

/// Adler-32 checksum with 4-byte big-endian output.
#[derive(Clone, Default)]
pub struct Adler32Digest(Vec<u8>);

impl HashMarker for Adler32Digest {}

impl OutputSizeUser for Adler32Digest {
    type OutputSize = U4;
}

impl Update for Adler32Digest {
    fn update(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
}

impl FixedOutput for Adler32Digest {
    fn finalize_into(self, out: &mut Output<Self>) {
        use adler2::Adler32;
        let mut h = Adler32::new();
        h.write_slice(&self.0);
        out.copy_from_slice(&h.checksum().to_be_bytes());
    }
}

// ── XXH3-128 → 16 bytes ──────────────────────────────────────────────────────

/// XXH3 128-bit hash with 16-byte big-endian output.
#[derive(Clone, Default)]
pub struct Xxh3Digest(Vec<u8>);

impl HashMarker for Xxh3Digest {}

impl OutputSizeUser for Xxh3Digest {
    type OutputSize = U16;
}

impl Update for Xxh3Digest {
    fn update(&mut self, data: &[u8]) {
        self.0.extend_from_slice(data);
    }
}

impl FixedOutput for Xxh3Digest {
    fn finalize_into(self, out: &mut Output<Self>) {
        use xxhash_rust::xxh3::xxh3_128;
        out.copy_from_slice(&xxh3_128(&self.0).to_be_bytes());
    }
}
