use digest::Digest;
use std::fmt;
use std::str::FromStr;

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
    Crc32c,
    Xxh3,
    Shake128,
    Shake256,
    Blake2b,
    Blake2s,
    Sm3,
    Streebog256,
    Streebog512,
    Ripemd160,
    Sha512_256,
    Sha512_224,
    K12,
    Adler32,
    Crc64,
}

impl Algorithm {
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
        ]
    }

    pub fn hashdeep_name(&self) -> &'static str {
        match self {
            Algorithm::Blake3 => "blake3",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
            Algorithm::Sha3_256 => "sha3-256",
            Algorithm::Sha1 => "sha1",
            Algorithm::Md5 => "md5",
            Algorithm::Tiger => "tiger",
            Algorithm::Whirlpool => "whirlpool",
            Algorithm::Ssdeep => "ssdeep",
            Algorithm::Tlsh => "tlsh",
            Algorithm::Crc32c => "crc32c",
            Algorithm::Xxh3 => "xxh3",
            Algorithm::Shake128 => "shake128",
            Algorithm::Shake256 => "shake256",
            Algorithm::Blake2b => "blake2b",
            Algorithm::Blake2s => "blake2s",
            Algorithm::Sm3 => "sm3",
            Algorithm::Streebog256 => "streebog256",
            Algorithm::Streebog512 => "streebog512",
            Algorithm::Ripemd160 => "ripemd160",
            Algorithm::Sha512_256 => "sha512-256",
            Algorithm::Sha512_224 => "sha512-224",
            Algorithm::K12 => "k12",
            Algorithm::Adler32 => "adler32",
            Algorithm::Crc64 => "crc64",
        }
    }

    pub fn is_fuzzy(&self) -> bool {
        matches!(self, Algorithm::Ssdeep | Algorithm::Tlsh)
    }

    pub fn is_non_cryptographic(&self) -> bool {
        matches!(
            self,
            Algorithm::Crc32c | Algorithm::Xxh3 | Algorithm::Adler32 | Algorithm::Crc64
        )
    }

    /// Returns true for algorithms that require reading the full file into memory
    /// before hashing — either because they are non-cryptographic (CRC32C, XXH3)
    /// or because they are XOFs (SHAKE-128, SHAKE-256) that cannot stream via
    /// the `DynHasher` trait, or because they use non-standard APIs.
    pub fn needs_full_read(&self) -> bool {
        matches!(
            self,
            Algorithm::Crc32c
                | Algorithm::Xxh3
                | Algorithm::Shake128
                | Algorithm::Shake256
                | Algorithm::K12
                | Algorithm::Adler32
                | Algorithm::Crc64
        )
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.hashdeep_name())
    }
}

impl FromStr for Algorithm {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "blake3" => Ok(Algorithm::Blake3),
            "sha256" | "sha-256" => Ok(Algorithm::Sha256),
            "sha512" | "sha-512" => Ok(Algorithm::Sha512),
            "sha3-256" | "sha3_256" => Ok(Algorithm::Sha3_256),
            "sha1" | "sha-1" => Ok(Algorithm::Sha1),
            "md5" => Ok(Algorithm::Md5),
            "tiger" => Ok(Algorithm::Tiger),
            "whirlpool" => Ok(Algorithm::Whirlpool),
            "ssdeep" => Ok(Algorithm::Ssdeep),
            "tlsh" => Ok(Algorithm::Tlsh),
            "crc32c" => Ok(Algorithm::Crc32c),
            "xxh3" => Ok(Algorithm::Xxh3),
            "shake128" => Ok(Algorithm::Shake128),
            "shake256" => Ok(Algorithm::Shake256),
            "blake2b" => Ok(Algorithm::Blake2b),
            "blake2s" => Ok(Algorithm::Blake2s),
            "sm3" => Ok(Algorithm::Sm3),
            "streebog256" => Ok(Algorithm::Streebog256),
            "streebog512" => Ok(Algorithm::Streebog512),
            "ripemd160" | "ripemd-160" => Ok(Algorithm::Ripemd160),
            "sha512-256" | "sha512_256" => Ok(Algorithm::Sha512_256),
            "sha512-224" | "sha512_224" => Ok(Algorithm::Sha512_224),
            "k12" | "kangaroo12" | "kangarootwelve" => Ok(Algorithm::K12),
            "adler32" => Ok(Algorithm::Adler32),
            "crc64" => Ok(Algorithm::Crc64),
            other => anyhow::bail!("unknown algorithm: {other}"),
        }
    }
}

pub fn hash_bytes(algo: Algorithm, data: &[u8]) -> String {
    match algo {
        Algorithm::Blake3 => blake3::hash(data).to_hex().to_string(),
        Algorithm::Sha256 => hex_digest::<sha2::Sha256>(data),
        Algorithm::Sha512 => hex_digest::<sha2::Sha512>(data),
        Algorithm::Sha3_256 => hex_digest::<sha3::Sha3_256>(data),
        Algorithm::Sha1 => hex_digest::<sha1::Sha1>(data),
        Algorithm::Md5 => hex_digest::<md5::Md5>(data),
        Algorithm::Tiger => hex_digest::<tiger::Tiger>(data),
        Algorithm::Whirlpool => hex_digest::<whirlpool::Whirlpool>(data),
        Algorithm::Ssdeep => crate::fuzzy::ssdeep::compute(data),
        Algorithm::Tlsh => crate::fuzzy::tlsh::compute(data).unwrap_or_default(),
        Algorithm::Crc32c => {
            let checksum = crc32c::crc32c(data);
            format!("{checksum:08x}")
        }
        Algorithm::Xxh3 => {
            use xxhash_rust::xxh3::xxh3_128;
            let hash = xxh3_128(data);
            format!("{hash:032x}")
        }
        Algorithm::Shake128 => {
            use sha3::digest::{ExtendableOutput, XofReader};
            let mut h = sha3::Shake128::default();
            sha3::digest::Update::update(&mut h, data);
            let mut reader = h.finalize_xof();
            let mut buf = [0u8; 32];
            reader.read(&mut buf);
            hex::encode(buf)
        }
        Algorithm::Shake256 => {
            use sha3::digest::{ExtendableOutput, XofReader};
            let mut h = sha3::Shake256::default();
            sha3::digest::Update::update(&mut h, data);
            let mut reader = h.finalize_xof();
            let mut buf = [0u8; 64];
            reader.read(&mut buf);
            hex::encode(buf)
        }
        Algorithm::Blake2b => hex_digest::<blake2::Blake2b512>(data),
        Algorithm::Blake2s => hex_digest::<blake2::Blake2s256>(data),
        Algorithm::Sm3 => hex_digest::<sm3::Sm3>(data),
        Algorithm::Streebog256 => hex_digest::<streebog::Streebog256>(data),
        Algorithm::Streebog512 => hex_digest::<streebog::Streebog512>(data),
        Algorithm::Ripemd160 => hex_digest::<ripemd::Ripemd160>(data),
        Algorithm::Sha512_256 => hex_digest::<sha2::Sha512_256>(data),
        Algorithm::Sha512_224 => hex_digest::<sha2::Sha512_224>(data),
        Algorithm::K12 => {
            use tiny_keccak::Hasher;
            let mut h = tiny_keccak::KangarooTwelve::new(b"");
            h.update(data);
            let mut out = [0u8; 32];
            h.finalize(&mut out);
            hex::encode(out)
        }
        Algorithm::Adler32 => {
            use adler2::Adler32;
            let mut h = Adler32::new();
            h.write_slice(data);
            format!("{:08x}", h.checksum())
        }
        Algorithm::Crc64 => {
            let checksum = crc::Crc::<u64>::new(&crc::CRC_64_ECMA_182).checksum(data);
            format!("{checksum:016x}")
        }
    }
}

fn hex_digest<D: Digest>(data: &[u8]) -> String {
    let mut hasher = D::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
