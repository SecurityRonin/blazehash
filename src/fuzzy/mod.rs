pub mod ssdeep;
pub mod tlsh;

use crate::algorithm::Algorithm;
use std::collections::HashMap;

/// Compute fuzzy hashes for all fuzzy algorithms in `algorithms`.
/// Non-fuzzy algorithms are ignored.
/// tlsh returns empty string for data that is too short or has insufficient entropy.
pub fn compute_fuzzy(data: &[u8], algorithms: &[Algorithm]) -> HashMap<Algorithm, String> {
    let mut results = HashMap::new();
    for &algo in algorithms {
        match algo {
            Algorithm::Ssdeep => {
                results.insert(algo, ssdeep::compute(data));
            }
            Algorithm::Tlsh => {
                results.insert(algo, tlsh::compute(data).unwrap_or_default());
            }
            _ => {}
        }
    }
    results
}
