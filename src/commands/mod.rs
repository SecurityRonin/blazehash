pub mod archive;
pub mod audit;
pub mod bench;
pub mod completions;
pub mod convert;
pub mod dedup;
pub mod export;
pub mod diff;
pub mod hash;
pub mod head;
#[cfg(feature = "docker")]
pub mod image;
pub mod lint;
pub mod merge;
pub mod normalize;
pub mod piecewise;
pub mod search;
pub mod selfcheck;
pub mod redact;
pub mod filter;
pub mod stats;
#[cfg(feature = "report")]
pub mod report;
pub mod size_only;
pub mod stdin;
pub mod update;
pub mod verify_image;
pub mod vt;
pub mod watch;

use blazehash::walk::WalkError;

/// Print walk/hash errors to stderr.
pub fn report_walk_errors(errors: &[WalkError]) {
    for err in errors {
        eprintln!("blazehash: warning: {}: {}", err.path.display(), err.error);
    }
}
