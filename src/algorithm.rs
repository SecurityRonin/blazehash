use std::fmt;
use std::str::FromStr;
use digest::Digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Blake3,
    Sha256,
    Sha512,
    Sha3_256,
    Sha1,
    Md5,
    Tiger,
    Whirlpool,
}

impl Algorithm {
    pub fn all() -> &'static [Algorithm] {
        &[
            Algorithm::Blake3, Algorithm::Sha256, Algorithm::Sha512,
            Algorithm::Sha3_256, Algorithm::Sha1, Algorithm::Md5,
            Algorithm::Tiger, Algorithm::Whirlpool,
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
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self { Algorithm::Blake3 }
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
            other => anyhow::bail!("unknown algorithm: {}", other),
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
    }
}

fn hex_digest<D: Digest>(data: &[u8]) -> String {
    let mut hasher = D::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
