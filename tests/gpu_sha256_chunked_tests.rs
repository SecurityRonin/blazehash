#[cfg(feature = "gpu")]
mod gpu_chunked_tests {
    use blazehash::gpu::backend::GpuBackend;
    use blazehash::gpu::sha256::GpuSha256;

    fn sha256_cpu(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        format!("{:x}", h.finalize())
    }

    #[test]
    fn test_gpu_sha256_chunked_matches_cpu_1mb() {
        let Some(backend) = GpuBackend::detect() else {
            eprintln!("No GPU — skipping chunked GPU sha256 test");
            return;
        };
        let gpu = GpuSha256::new(&backend);

        // 1 MiB of deterministic data (> single-block but < 64 MiB threshold)
        let data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
        let gpu_result = gpu.hash_chunked(&data).unwrap();
        let cpu_result = sha256_cpu(&data);
        assert_eq!(gpu_result, cpu_result, "1 MiB chunked GPU must match CPU SHA-256");
    }

    #[test]
    fn test_gpu_sha256_chunked_matches_single_shot_small() {
        let Some(backend) = GpuBackend::detect() else {
            eprintln!("No GPU — skipping chunked GPU sha256 test");
            return;
        };
        let gpu = GpuSha256::new(&backend);

        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let single = gpu.hash(&data);
        let chunked = gpu.hash_chunked(&data).unwrap();
        assert_eq!(single, chunked, "small data: chunked must match single-shot");
    }

    #[test]
    fn test_gpu_sha256_chunked_matches_cpu_exact_batch_boundary() {
        let Some(backend) = GpuBackend::detect() else {
            eprintln!("No GPU — skipping chunked GPU sha256 test");
            return;
        };
        let gpu = GpuSha256::new(&backend);

        // Exactly 64 KiB (1024 blocks x 64 bytes) — tests boundary condition
        let data: Vec<u8> = vec![0xABu8; 64 * 1024];
        let gpu_result = gpu.hash_chunked(&data).unwrap();
        let cpu_result = sha256_cpu(&data);
        assert_eq!(gpu_result, cpu_result, "exact batch boundary must match CPU");
    }

    #[test]
    fn test_gpu_sha256_chunked_empty() {
        let Some(backend) = GpuBackend::detect() else {
            eprintln!("No GPU — skipping chunked GPU sha256 test");
            return;
        };
        let gpu = GpuSha256::new(&backend);

        let gpu_result = gpu.hash_chunked(&[]).unwrap();
        let cpu_result = sha256_cpu(&[]);
        assert_eq!(gpu_result, cpu_result, "empty input must match CPU SHA-256");
    }
}
