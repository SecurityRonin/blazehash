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
    #[cfg(feature = "hashdb")]
    #[arg(long = "nsrl-hsh", value_name = "FILE")]
    pub nsrl_hsh: Option<PathBuf>,

    /// Known-bad hash list file (one SHA-256 or SHA-1 per line)
    #[cfg(feature = "hashdb")]
    #[arg(long = "hashdb-bad", value_name = "FILE")]
    pub hashdb_bad: Option<std::path::PathBuf>,

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

    /// Exit non-zero if any file encountered during audit has no entry in the known manifest
    #[arg(long = "fail-on-unknown")]
    pub fail_on_unknown: bool,

    /// Minimum number of valid cosignatures required by `verify-msig`
    #[arg(long = "threshold", default_value = "1")]
    pub threshold: usize,

    /// Output diff in unified patch format
    #[arg(long = "patch")]
    pub patch: bool,

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

    /// YARA rules file to scan files during hashing
    #[cfg(feature = "yara")]
    #[arg(
        long = "yara",
        value_name = "FILE",
        help = "YARA rules file to scan files during hashing"
    )]
    pub yara: Option<PathBuf>,

    /// Maximum file size in MB for YARA scanning; files above this are skipped (default: 256)
    #[cfg(feature = "yara")]
    #[arg(
        long = "yara-max-size",
        value_name = "MB",
        default_value = "256",
        help = "Maximum file size (MB) for YARA scanning; larger files skip YARA"
    )]
    pub yara_max_size: u64,

    /// Annotate each file against the forensicnomicon CATALOG (triage priority, MITRE, artifact type)
    #[arg(
        long = "nomicon",
        help = "Annotate hashed files with forensicnomicon catalog metadata (triage, MITRE, artifact type)"
    )]
    pub nomicon: bool,

    /// Compile and use all forensicnomicon catalog YARA rules in addition to any --yara rules file
    #[cfg(feature = "yara")]
    #[arg(
        long = "yara-catalog",
        help = "Compile forensicnomicon catalog YARA rules and scan files"
    )]
    pub yara_catalog: bool,

    /// VirusTotal API key (for `blazehash vt`; falls back to VT_API_KEY env var)
    #[arg(long = "api-key", value_name = "KEY")]
    pub api_key: Option<String>,

    /// Examiner name for chain-of-custody metadata in manifest header and HTML report
    #[arg(long = "examiner", value_name = "NAME")]
    pub examiner: Option<String>,

    /// Case identifier for chain-of-custody metadata in manifest header and HTML report
    #[arg(long = "case", value_name = "ID")]
    pub case_id: Option<String>,

    /// Force-enable progress bar (auto-enabled on TTY)
    #[arg(long = "progress")]
    pub progress: bool,

    /// File path for file-proof / verify-proof subcommands
    #[arg(long = "path", value_name = "PATH")]
    pub merkle_path: Option<String>,

    /// SHA-256 hex value for verify-proof / check-file subcommands
    #[arg(long = "sha256", value_name = "HEX")]
    pub merkle_sha256: Option<String>,

    /// Comma-separated file paths for `disclose` subcommand
    #[arg(long = "paths", value_name = "PATHS")]
    pub disclose_paths: Option<String>,

    /// JSON proof array for verify-proof subcommand
    #[arg(long = "proof", value_name = "JSON")]
    pub merkle_proof: Option<String>,

    /// Root hex for verify-proof subcommand
    #[arg(long = "root", value_name = "HEX")]
    pub merkle_root: Option<String>,

    /// Sector size for raw device hashing (default: 512)
    #[arg(long = "sector-size", default_value = "512")]
    pub sector_size: usize,

    /// Output as JSON (for stats subcommand)
    #[arg(long = "json")]
    pub json: bool,

    /// Filter by algorithm name (for filter subcommand)
    #[arg(long = "algo", value_name = "ALGO")]
    pub filter_algo: Option<String>,

    /// Strip path prefix from all entries (for normalize subcommand)
    #[arg(long = "strip-prefix", value_name = "PREFIX")]
    pub strip_prefix: Option<String>,

    /// Add path prefix to all entries (for normalize subcommand)
    #[arg(long = "add-prefix", value_name = "PREFIX")]
    pub add_prefix: Option<String>,

    /// Source format for convert subcommand (sha256sum, md5sum, sha1sum, hashdeep, sfv)
    #[arg(long = "from", value_name = "FORMAT")]
    pub from_format: Option<String>,

    /// Number of entries to output for head subcommand (default: 10)
    #[arg(long = "count", short = 'n', default_value = "10")]
    pub count: usize,

    /// Path substring to search for (search subcommand)
    #[arg(long = "search-path", value_name = "QUERY")]
    pub search_path: Option<String>,

    /// Hash prefix to search for (search subcommand)
    #[arg(long = "hash", value_name = "PREFIX")]
    pub search_hash: Option<String>,

    /// Case-insensitive search
    #[arg(long = "ignore-case", short = 'i')]
    pub ignore_case: bool,

    /// Export format: csv, tsv, jsonl (for export subcommand)
    #[arg(long = "export-format", value_name = "FORMAT")]
    pub export_format: Option<String>,

    /// Field to sort by for sort subcommand: path, hash, algo, ext (default: path)
    #[arg(long = "sort-by", value_name = "FIELD", default_value = "path")]
    pub sort_by: String,

    /// Filter by algorithm name for verify subcommand
    #[arg(long = "verify-algo", value_name = "ALGO")]
    pub verify_algo: Option<String>,

    /// Set a header key=value (tag subcommand, repeatable)
    #[arg(long = "set", value_name = "KEY=VALUE")]
    pub tag_set: Vec<String>,

    /// Remove a header key (tag subcommand, repeatable)
    #[arg(long = "unset", value_name = "KEY")]
    pub tag_unset: Vec<String>,

    /// Number of entries per chunk file for split subcommand (default: 1000)
    #[arg(long = "chunk", default_value = "1000")]
    pub split_chunk: usize,

    /// Number of parts for blazehash balance
    #[arg(long = "parts")]
    pub balance_parts: Option<usize>,

    /// Algorithm to pivot on (for `blazehash pivot`)
    #[arg(long = "pivot-algo")]
    pub pivot_algo: Option<String>,

    /// Substring to replace in paths (for `blazehash rename`)
    #[arg(long = "rename-from")]
    pub rename_from: Option<String>,

    /// Replacement string for --rename-from (default: empty string)
    #[arg(long = "rename-to", default_value = "")]
    pub rename_to: String,

    /// Offset for slice subcommand (skip first N entries)
    #[arg(long = "offset", default_value = "0")]
    pub slice_offset: usize,

    /// Regex pattern to match against path or hash (for `blazehash grep`)
    #[arg(long = "pattern")]
    pub grep_pattern: Option<String>,

    /// Key to group entries by for tally subcommand (ext, dir, algo)
    #[arg(long = "tally-by", value_name = "FIELD", default_value = "ext",
          value_parser = ["ext", "dir", "algo"])]
    pub tally_by: String,

    /// Glob pattern to exclude entries for exclude subcommand
    #[arg(long = "exclude-pattern", value_name = "GLOB")]
    pub exclude_pattern: Option<String>,

    /// Filter by algorithm for hash-only subcommand
    #[arg(long = "hash-only-algo", value_name = "ALGO")]
    pub hash_only_algo: Option<String>,

    /// Note message for blazehash annotate
    #[arg(long = "note")]
    pub annotate_note: Option<String>,

    /// Seed for blazehash shuffle (reproducible output)
    #[arg(long = "seed")]
    pub shuffle_seed: Option<u64>,

    /// Remote backend config overrides (KEY=VALUE, repeatable).
    /// Example: --remote-config region=eu-west-1 --remote-config endpoint=http://localhost:9000
    #[arg(long = "remote-config", value_name = "KEY=VALUE")]
    pub remote_config: Vec<String>,
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
    PqSign,
    PqVerifySig,
    Cosign,
    VerifyMsig,
    Merge,
    Update,
    Vt,
    Watch,
    #[cfg(feature = "report")]
    Report,
    Completions,
    Merkle,
    MerkleProof,
    MerkleVerify,
    Disclose,
    ProveMembership,
    #[cfg(feature = "ots")]
    OtsStamp,
    #[cfg(feature = "ots")]
    OtsVerify,
    #[cfg(feature = "tui")]
    Tui,
    #[cfg(feature = "qr")]
    Qr,
    Timeline,
    Lint,
    Redact,
    Sample,
    Stats,
    Filter,
    Normalize,
    Selfcheck,
    Archive,
    Convert,
    Head,
    Tail,
    Search,
    Export,
    Sort,
    Intersect,
    Subtract,
    ApplyPatch,
    Verify,
    Info,
    Missing,
    Tag,
    Count,
    Cat,
    Split,
    Uniq,
    Checksum,
    Pivot,
    Rename,
    Slice,
    Stamp,
    Grep,
    Tally,
    Exclude,
    Contains,
    PathOnly,
    HashOnly,
    Duplicates,
    Repair,
    SymDiff,
    First,
    Annotate,
    Shuffle,
    Reverse,
    UniqueHash,
    Balance,
    Interleave,
    GDriveCollect,
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
            == Some(std::ffi::OsStr::new("pq-sign"))
        {
            Mode::PqSign
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("pq-verify-sig"))
        {
            Mode::PqVerifySig
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("cosign"))
        {
            Mode::Cosign
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("verify-msig"))
        {
            Mode::VerifyMsig
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("merge")) {
            Mode::Merge
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("update"))
        {
            Mode::Update
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("watch")) {
            Mode::Watch
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("report"))
        {
            #[cfg(feature = "report")]
            return Mode::Report;
            #[cfg(not(feature = "report"))]
            Mode::Hash
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("vt")) {
            Mode::Vt
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("completions"))
        {
            Mode::Completions
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("tui")) {
            #[cfg(feature = "tui")]
            return Mode::Tui;
            #[cfg(not(feature = "tui"))]
            return Mode::Hash;
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("file-proof"))
        {
            Mode::MerkleProof
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("verify-proof"))
        {
            Mode::MerkleVerify
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("seal"))
        {
            Mode::Merkle
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("qr")) {
            #[cfg(feature = "qr")]
            return Mode::Qr;
            #[cfg(not(feature = "qr"))]
            return Mode::Hash;
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("disclose"))
        {
            Mode::Disclose
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("check-file"))
        {
            Mode::ProveMembership
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("timeline"))
        {
            Mode::Timeline
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("lint")) {
            Mode::Lint
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("redact"))
        {
            Mode::Redact
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("sample"))
        {
            Mode::Sample
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("stats"))
        {
            Mode::Stats
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("filter"))
        {
            Mode::Filter
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("normalize"))
        {
            Mode::Normalize
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("selfcheck"))
        {
            Mode::Selfcheck
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("archive"))
        {
            Mode::Archive
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("convert"))
        {
            Mode::Convert
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("head")) {
            Mode::Head
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("tail")) {
            Mode::Tail
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("search"))
        {
            Mode::Search
        } else if self.paths.first().map(|p| p.as_os_str())
            == Some(std::ffi::OsStr::new("export"))
        {
            Mode::Export
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("sort")) {
            Mode::Sort
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("intersect")) {
            Mode::Intersect
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("subtract")) {
            Mode::Subtract
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("apply-patch")) {
            Mode::ApplyPatch
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("verify")) {
            Mode::Verify
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("ots")) {
            match self.paths.get(1).and_then(|p| p.to_str()) {
                Some("stamp") => {
                    #[cfg(feature = "ots")]
                    return Mode::OtsStamp;
                    #[cfg(not(feature = "ots"))]
                    return Mode::Hash;
                }
                Some("verify") => {
                    #[cfg(feature = "ots")]
                    return Mode::OtsVerify;
                    #[cfg(not(feature = "ots"))]
                    return Mode::Hash;
                }
                _ => return Mode::Hash,
            }
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("info")) {
            Mode::Info
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("missing")) {
            Mode::Missing
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("tag")) {
            Mode::Tag
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("count")) {
            Mode::Count
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("cat")) {
            Mode::Cat
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("split")) {
            Mode::Split
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("uniq")) {
            Mode::Uniq
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("checksum")) {
            Mode::Checksum
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("pivot")) {
            Mode::Pivot
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("rename")) {
            Mode::Rename
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("slice")) {
            Mode::Slice
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("stamp")) {
            Mode::Stamp
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("grep")) {
            Mode::Grep
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("tally")) {
            Mode::Tally
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("exclude")) {
            Mode::Exclude
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("contains")) {
            Mode::Contains
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("path-only")) {
            Mode::PathOnly
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("hash-only")) {
            Mode::HashOnly
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("duplicates")) {
            Mode::Duplicates
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("repair")) {
            Mode::Repair
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("sym-diff")) {
            Mode::SymDiff
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("first")) {
            Mode::First
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("annotate")) {
            Mode::Annotate
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("shuffle")) {
            Mode::Shuffle
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("reverse")) {
            Mode::Reverse
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("unique-hash")) {
            Mode::UniqueHash
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("balance")) {
            Mode::Balance
        } else if self.paths.first().map(|p| p.as_os_str()) == Some(std::ffi::OsStr::new("interleave")) {
            Mode::Interleave
        } else if self.paths.first().map(|p| {
                let s = p.to_string_lossy();
                s.starts_with("gdrive://")
                    || s.starts_with("https://drive.google.com/")
                    || s.starts_with("http://drive.google.com/")
            }) == Some(true)
        {
            #[cfg(feature = "remote")]
            return Mode::GDriveCollect;
            #[cfg(not(feature = "remote"))]
            {
                eprintln!(
                    "error: gdrive requires the `remote` feature \
                     — recompile with --features remote"
                );
                std::process::exit(1);
            }
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
