pub mod annotate;
pub mod apply_patch;
pub mod stamp;
pub mod cat;
pub mod checksum;
pub mod count;
pub mod info;
pub mod missing;
pub mod split;
pub mod tag;
pub mod uniq;
pub mod archive;
pub mod audit;
pub mod intersect;
pub mod subtract;
pub mod bench;
pub mod completions;
pub mod convert;
pub mod dedup;
pub mod export;
pub mod diff;
pub mod hash;
pub mod head;
pub mod tail;
#[cfg(feature = "docker")]
pub mod image;
pub mod lint;
pub mod merge;
pub mod normalize;
pub mod piecewise;
pub mod search;
pub mod selfcheck;
pub mod redact;
pub mod repair;
pub mod sample;
pub mod sym_diff;
pub mod exclude;
pub mod filter;
pub mod stats;
#[cfg(feature = "report")]
pub mod report;
pub mod hash_only;
pub mod path_only;
pub mod size_only;
pub mod sort;
pub mod stdin;
pub mod update;
pub mod pivot;
pub mod contains_cmd;
pub mod grep_cmd;
pub mod rename_cmd;
pub mod slice_cmd;
pub mod duplicates;
pub mod first_cmd;
pub mod tally;
pub mod verify;
pub mod verify_image;
pub mod vt;
pub mod watch;

use anyhow::Result;
use blazehash::walk::WalkError;

/// Print walk/hash errors to stderr.
pub fn report_walk_errors(errors: &[WalkError]) {
    for err in errors {
        eprintln!("blazehash: warning: {}: {}", err.path.display(), err.error);
    }
}

/// Return a writer for `path` (file) or stdout when `path` is `None`.
pub fn output_writer(path: Option<&std::path::Path>) -> Result<Box<dyn std::io::Write>> {
    match path {
        Some(p) => Ok(Box::new(std::fs::File::create(p)?)),
        None => Ok(Box::new(std::io::stdout())),
    }
}
