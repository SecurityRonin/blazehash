pub mod annotate;
pub mod apply_patch;
pub mod archive;
pub mod audit;
pub mod balance;
pub mod bench;
pub mod cat;
pub mod checksum;
pub mod completions;
pub mod contains_cmd;
pub mod convert;
pub mod count;
pub mod dedup;
pub mod diff;
pub mod duplicates;
pub mod exclude;
pub mod export;
pub mod filter;
pub mod first_cmd;
pub mod grep_cmd;
pub mod hash;
pub mod hash_only;
pub mod head;
#[cfg(feature = "docker")]
pub mod image;
pub mod info;
pub mod interleave;
pub mod intersect;
pub mod lint;
pub mod merge;
pub mod missing;
pub mod normalize;
pub mod path_only;
pub mod piecewise;
pub mod pivot;
pub mod redact;
pub mod rename_cmd;
pub mod repair;
#[cfg(feature = "report")]
pub mod report;
pub mod reverse;
pub mod sample;
pub mod search;
pub mod selfcheck;
pub mod shuffle;
pub mod size_only;
pub mod slice_cmd;
pub mod sort;
pub mod split;
pub mod stamp;
pub mod stats;
pub mod stdin;
pub mod subtract;
pub mod sym_diff;
pub mod tag;
pub mod tail;
pub mod tally;
pub mod uniq;
pub mod unique_hash;
pub mod update;
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
///
/// When the `remote` feature is enabled and `path` is a remote URI (e.g. `s3://`, `mem://`),
/// returns a buffered [`blazehash::remote::writer::RemoteWriter`] that uploads atomically on drop.
pub fn output_writer(path: Option<&std::path::Path>) -> Result<Box<dyn std::io::Write>> {
    blazehash::output::output_writer(path)
}
