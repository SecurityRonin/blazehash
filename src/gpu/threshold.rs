use crate::algorithm::Algorithm;
use crate::gpu::config::GpuConfigState;

/// Algorithms supported by GPU acceleration.
/// BLAKE3 is excluded: its internal tree parallelism already saturates CPU memory bandwidth.
pub const GPU_ALGOS: &[Algorithm] = &[Algorithm::Sha256, Algorithm::Md5];

/// Decide whether to use the GPU for a hash operation.
///
/// - `file_size_mb`: file size in megabytes
/// - `algos`: algorithms requested
/// - `state`: current GPU config state
///
/// Returns true only when:
/// - State is UseThresholds (not Skip or NeedsCalibration)
/// - At least one requested algorithm is GPU-eligible
/// - File size meets the relevant threshold:
///   - 1 GPU-eligible algo: file_size_mb >= threshold_single_mb
///   - 2+ GPU-eligible algos: file_size_mb >= threshold_multi_mb
pub fn should_use_gpu(file_size_mb: u64, algos: &[Algorithm], state: &GpuConfigState) -> bool {
    let (single_mb, multi_mb) = match state {
        GpuConfigState::UseThresholds { single_mb, multi_mb } => (*single_mb as u64, *multi_mb as u64),
        _ => return false,
    };

    let gpu_algo_count = algos.iter().filter(|a| GPU_ALGOS.contains(a)).count();

    if gpu_algo_count == 0 {
        return false;
    }

    if gpu_algo_count >= 2 {
        file_size_mb >= multi_mb
    } else {
        file_size_mb >= single_mb
    }
}
