pub mod audit;
pub mod hash;
pub mod piecewise;
pub mod size_only;
pub mod verify_image;

use blazehash::walk::WalkError;

/// Print walk/hash errors to stderr.
pub fn report_walk_errors(errors: &[WalkError]) {
    for err in errors {
        eprintln!("blazehash: warning: {}: {}", err.path.display(), err.error);
    }
}
