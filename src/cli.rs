use blazehash::algorithm::Algorithm;
use clap::Parser;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(
    name = "blazehash",
    version,
    about = "Forensic file hasher — hashdeep for the modern era"
)]
pub struct Cli {
    /// Files or directories to hash
    #[arg()]
    pub paths: Vec<PathBuf>,

    /// Hash algorithms (comma-separated). Default: blake3
    #[arg(short = 'c', long = "compute", value_parser = parse_algorithms, default_value = "blake3")]
    pub algorithms: Vec<Vec<Algorithm>>,

    /// Recursive mode
    #[arg(short = 'r', long = "recursive")]
    pub recursive: bool,

    /// Output file (default: stdout). Bare -o (no filename) auto-derives
    /// <dirname>.hash for a single directory, or manifest.hash otherwise.
    #[arg(short = 'o', long = "output", num_args = 0..=1, default_missing_value = "__auto__")]
    pub output: Option<PathBuf>,

    /// Audit mode — verify files against known hashes
    #[arg(short = 'a', long = "audit")]
    pub audit: bool,

    /// Known hash file(s) for audit mode
    #[arg(short = 'k', long = "known")]
    pub known: Vec<PathBuf>,

    /// Verify forensic disk image integrity (E01/EWF)
    #[arg(long = "verify-image")]
    pub verify_image: bool,

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

    /// Hash data from stdin instead of files
    #[arg(long = "stdin")]
    pub stdin: bool,

    /// Bypass OS page cache for direct disk reads (forensic acquisition)
    #[arg(long = "no-cache")]
    pub no_cache: bool,

    /// Force CPU hashing even when GPU is available
    #[arg(long = "no-gpu")]
    pub no_gpu: bool,

    /// Output format
    #[arg(long = "format", default_value = "hashdeep")]
    pub format: String,

    /// Run GPU calibration benchmark (used with `blazehash bench`)
    #[arg(long = "gpu", help = "Run GPU calibration benchmark")]
    pub gpu: bool,

    /// Use conservative defaults; do not run benchmark or write config (used with `blazehash bench`)
    #[arg(
        long = "no-calibrate",
        help = "Use conservative defaults; do not run benchmark or write config"
    )]
    pub no_calibrate: bool,

    /// Minimum similarity % to consider a fuzzy match in audit mode (0-100, default: 50)
    #[arg(long = "fuzzy-threshold", default_value = "50", value_parser = clap::value_parser!(u32).range(0..=100))]
    pub fuzzy_threshold: u32,

    /// Show top N fuzzy matches per file in audit mode (default: 5)
    #[arg(long = "fuzzy-top", default_value = "5")]
    pub fuzzy_top: usize,

    /// Only hash files larger than this size (e.g. 1K, 10M, 2G)
    #[arg(long = "min-size", value_parser = parse_chunk_size)]
    pub min_size: Option<usize>,

    /// Only hash files smaller than this size (e.g. 100M, 4G)
    #[arg(long = "max-size", value_parser = parse_chunk_size)]
    pub max_size: Option<usize>,

    /// Only hash files modified after DATE (format: YYYY-MM-DD)
    #[arg(long = "newer", value_parser = parse_date)]
    pub newer: Option<std::time::SystemTime>,

    /// Include only files matching GLOB pattern (repeatable)
    #[arg(long = "include")]
    pub include: Vec<String>,

    /// Exclude files matching GLOB pattern (repeatable, overrides --include)
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,

    /// Hash NTFS Alternate Data Streams alongside main file content (Windows only, no-op elsewhere)
    #[arg(long = "ads")]
    pub ads: bool,

    /// Print one representative per duplicate group
    #[arg(long = "dedup-unique")]
    pub dedup_unique: bool,

    /// Print only files that have duplicates
    #[arg(long = "dedup-dupes")]
    pub dedup_dupes: bool,

    /// Path to NSRL SQLite database (.db)
    #[arg(long = "nsrl", value_name = "FILE")]
    pub nsrl: Option<PathBuf>,

    /// NIST NSRL .hsh flat hashset file (pipe-delimited)
    #[cfg(feature = "nsrl")]
    #[arg(long = "nsrl-hsh", value_name = "FILE")]
    pub nsrl_hsh: Option<PathBuf>,

    /// Suppress known-good files from output (requires --nsrl)
    #[arg(long = "nsrl-exclude")]
    pub nsrl_exclude: bool,

    /// Expected public key hex for verify-sig / audit auto-verify
    #[arg(long = "expected-pubkey", value_name = "HEX")]
    pub expected_pubkey: Option<String>,

    /// Sign manifest after writing (requires --output)
    #[arg(long = "sign")]
    pub sign: bool,

    /// Skip manifest signature auto-verification in audit mode
    #[arg(long = "ignore-sig")]
    pub ignore_sig: bool,

    /// Folder diff comparison method: content (XXH3-128, default), paranoid (BLAKE3), size-time, name
    #[arg(long = "compare-by", default_value = "content", value_parser = ["content", "paranoid", "size-time", "name"])]
    pub compare_by: String,

    /// Show identical files in folder diff output (hidden by default)
    #[arg(long = "show-identical")]
    pub show_identical: bool,

    /// Use NTFS $MFT direct read for size-only mode (Windows only, requires Admin).
    /// If not already elevated, a UAC prompt will appear to escalate privileges.
    #[arg(long = "mft")]
    pub mft: bool,

    /// [Internal] Elevated MFT worker: write TSV size results to FILE, then exit.
    /// This flag is passed automatically when spawning an elevated subprocess via UAC.
    #[arg(long = "_mft-worker", value_name = "FILE", hide = true)]
    pub mft_worker_output: Option<PathBuf>,

    /// Compute Shannon entropy for each file (H = -Σ p_i log2(p_i), range 0.0–8.0)
    #[arg(long = "entropy", help = "Compute Shannon entropy for each file")]
    pub entropy: bool,
}

pub fn parse_chunk_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    let (num_str, multiplier) = if s.ends_with('G') || s.ends_with('g') {
        (&s[..s.len() - 1], 1024 * 1024 * 1024)
    } else if s.ends_with('M') || s.ends_with('m') {
        (&s[..s.len() - 1], 1024 * 1024)
    } else if s.ends_with('K') || s.ends_with('k') {
        (&s[..s.len() - 1], 1024)
    } else {
        (s, 1usize)
    };
    let num: usize = num_str
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    Ok(num * multiplier)
}

fn parse_date(s: &str) -> Result<std::time::SystemTime, String> {
    let d = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|e| format!("invalid date {s:?}: {e}"))?;
    let dt = d.and_hms_opt(0, 0, 0).unwrap();
    let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    let secs = (dt - epoch).num_seconds() as u64;
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
}

fn parse_algorithms(s: &str) -> Result<Vec<Algorithm>, String> {
    s.split(',')
        .map(|name| Algorithm::from_str(name.trim()).map_err(|e| e.to_string()))
        .collect()
}

#[derive(Debug)]
pub enum Mode {
    Mcp,
    Bench,
    Diff,
    Dedup,
    NsrlBuildBloom,
    SizeOnly,
    Audit,
    VerifyImage,
    Piecewise,
    Stdin,
    Sign,
    VerifySig,
    Merge,
    Update,
    Hash,
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

    /// Resolve the `-o` value to a concrete path, handling the `__auto__` sentinel.
    pub fn resolve_output(&self) -> Option<PathBuf> {
        let raw = self.output.as_ref()?;
        if raw.as_os_str() != "__auto__" {
            return Some(raw.clone());
        }
        let name = self
            .paths
            .iter()
            .find(|p| p.is_dir() || p.exists())
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .filter(|n| *n != "." && *n != "..")
            .unwrap_or("manifest");
        Some(PathBuf::from(format!("{name}.hash")))
    }

    pub fn build_walk_filter(&self) -> anyhow::Result<blazehash::walk_filter::WalkFilter> {
        let mut b = blazehash::walk_filter::WalkFilter::builder();
        for pat in &self.include {
            b = b.include(pat);
        }
        for pat in &self.exclude {
            b = b.exclude(pat);
        }
        if let Some(min) = self.min_size {
            b = b.min_size(min as u64);
        }
        if let Some(max) = self.max_size {
            b = b.max_size(max as u64);
        }
        if let Some(newer) = self.newer {
            b = b.newer_than(newer);
        }
        b.build()
    }

    pub fn mode(&self) -> Mode {
        if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("mcp")) {
            Mode::Mcp
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("bench")) {
            Mode::Bench
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("diff")) {
            Mode::Diff
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("dedup")) {
            Mode::Dedup
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("nsrl"))
            && self.paths.get(1).and_then(|p| p.to_str()) == Some("build-bloom")
        {
            Mode::NsrlBuildBloom
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("sign")) {
            Mode::Sign
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("verify-sig"))
        {
            Mode::VerifySig
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("merge"))
        {
            Mode::Merge
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("update"))
        {
            Mode::Update
        } else if self.size_only {
            Mode::SizeOnly
        } else if self.audit {
            Mode::Audit
        } else if self.verify_image {
            Mode::VerifyImage
        } else if self.piecewise.is_some() {
            Mode::Piecewise
        } else if self.stdin {
            Mode::Stdin
        } else {
            Mode::Hash
        }
    }
}
