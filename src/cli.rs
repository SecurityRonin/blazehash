use blazehash::algorithm::Algorithm;
use clap::Parser;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(name = "blazehash", version, about = "Forensic file hasher — hashdeep for the modern era")]
pub struct Cli {
    /// Files or directories to hash
    #[arg(required_unless_present = "version")]
    pub paths: Vec<PathBuf>,

    /// Hash algorithms (comma-separated). Default: blake3
    #[arg(short = 'c', long = "compute", value_parser = parse_algorithms, default_value = "blake3")]
    pub algorithms: Vec<Vec<Algorithm>>,

    /// Recursive mode
    #[arg(short = 'r', long = "recursive")]
    pub recursive: bool,

    /// Output file (default: stdout)
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Audit mode — verify files against known hashes
    #[arg(short = 'a', long = "audit")]
    pub audit: bool,

    /// Known hash file(s) for audit mode
    #[arg(short = 'k', long = "known")]
    pub known: Vec<PathBuf>,

    /// Size-only mode (no hashing)
    #[arg(short = 's', long = "size-only")]
    pub size_only: bool,

    /// Bare output (no header, no comments)
    #[arg(short = 'b', long = "bare")]
    pub bare: bool,

    /// Piecewise hashing chunk size (e.g. 1G, 100M)
    #[arg(short = 'p', long = "piecewise")]
    pub piecewise: Option<String>,

    /// Resume from a partial manifest (skip already-hashed files)
    #[arg(long = "resume")]
    pub resume: bool,

    /// Output format
    #[arg(long = "format", default_value = "hashdeep")]
    pub format: String,
}

pub fn parse_chunk_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    let (num_str, multiplier) = if s.ends_with('G') || s.ends_with('g') {
        (&s[..s.len()-1], 1024 * 1024 * 1024)
    } else if s.ends_with('M') || s.ends_with('m') {
        (&s[..s.len()-1], 1024 * 1024)
    } else if s.ends_with('K') || s.ends_with('k') {
        (&s[..s.len()-1], 1024)
    } else {
        (s, 1usize)
    };
    let num: usize = num_str.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
    Ok(num * multiplier)
}

fn parse_algorithms(s: &str) -> Result<Vec<Algorithm>, String> {
    s.split(',')
        .map(|name| Algorithm::from_str(name.trim()).map_err(|e| e.to_string()))
        .collect()
}

impl Cli {
    pub fn flat_algorithms(&self) -> Vec<Algorithm> {
        let flat: Vec<Algorithm> = self.algorithms.iter().flatten().copied().collect();
        if flat.is_empty() {
            vec![Algorithm::Blake3]
        } else {
            flat
        }
    }
}
