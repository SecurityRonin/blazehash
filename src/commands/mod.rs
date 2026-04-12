pub mod audit;
pub mod bench;
pub mod dedup;
pub mod diff;
pub mod hash;
pub mod merge;
pub mod piecewise;
pub mod size_only;
pub mod stdin;
pub mod verify_image;

use blazehash::walk::WalkError;

/// Print walk/hash errors to stderr.
pub fn report_walk_errors(errors: &[WalkError]) {
    for err in errors {
        eprintln!("blazehash: warning: {}: {}", err.path.display(), err.error);
    }
}
