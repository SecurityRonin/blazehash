# Platform Performance Design

**Date:** 2026-04-09
**Status:** Approved

## Overview

Four complementary performance improvements targeting Windows I/O, GPU-accelerated hashing, direct I/O (cache bypass), and large page support. All implemented with strict TDD (red-green-refactor, separate commits).

---

## 1. Windows IOCP Async I/O

### Problem

The current rayon + mmap pipeline is synchronous. On Windows, this misses IOCP (I/O Completion Ports) — the OS mechanism for queuing thousands of concurrent I/O operations with minimal threads. The gap is most visible when hashing thousands of small files.

### Decision

Platform-split: tokio + IOCP on Windows only. rayon + mmap unchanged on Linux/Mac where it is already near-optimal (io_uring is too risky for forensic environments; kqueue/epoll do not provide true async file I/O).

### Design

New module `src/io/`:

```
src/io/
  mod.rs        — FileReader trait: read_file(path) → Result<Bytes>
  standard.rs   — rayon + mmap (Linux/Mac, and Windows fallback)
  windows.rs    — tokio + IOCP (Windows only, cfg-gated)
```

`windows.rs` implementation:
- `tokio::fs::File` uses IOCP under the hood — no manual IOCP registration required
- Bounded semaphore (default 256) limits concurrent open handles
- `tokio::task::spawn_blocking` bridges async I/O dispatch into the existing synchronous CPU hashing code — I/O is async, hashing stays on rayon
- `#[cfg(target_os = "windows")]` gates the entire module

Cargo dependency, Windows only:
```toml
[target.'cfg(target_os = "windows")'.dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "fs", "sync"] }
```

No binary size increase on Linux/Mac.

### TDD

- Unit: mock filesystem, verify semaphore enforces concurrency limit
- Integration: hash 1000 temp files via Windows path, assert output identical to standard path
- All tests compile cross-platform; IOCP path exercised on Windows CI only

---

## 2. GPU-Accelerated Hashing

### Supported Algorithms

SHA-256 and MD5 — both are well-suited to GPU parallelism and are common in forensic workflows. BLAKE3 is excluded: its internal tree parallelism already saturates CPU memory bandwidth and its structure is not efficiently GPU-parallelisable.

### Feature Flag

```toml
[features]
gpu = ["dep:wgpu", "dep:pollster"]
```

Off by default — wgpu is a heavy dependency and many forensic systems have no GPU. `pollster` bridges wgpu's async API into the synchronous hashing pipeline without requiring tokio on non-Windows platforms.

### Auto-Selection (Threshold-Based)

GPU is selected automatically when either condition is met:
- File ≥ threshold_single_mb AND a GPU-supported algorithm is selected
- File ≥ threshold_multi_mb AND 3+ algorithms selected simultaneously

Otherwise CPU is used. `--no-gpu` disables GPU explicitly.

Thresholds are calibrated per-device and stored in config (see §2.3). Shipped conservative defaults are set from benchmarks on a Paperspace RTX A5000 (representative of a self-built forensic workstation with a gaming/workstation card on PCIe 4.0).

### GPU Adapter Decision Tree

On every run (when `gpu` feature is compiled in):

```
wgpu enumerate adapters
│
├── No adapter found
│   └── CPU path. Config untouched (GPU may return — eGPU case).
│
├── Software renderer only (WARP / llvmpipe)
│   └── CPU path. No config written.
│
└── Any real GPU (integrated or discrete — no distinction made)
    ├── No config → auto-calibrate → write config
    ├── Config: same device, gpu_enabled=true → use calibrated thresholds
    ├── Config: same device, gpu_enabled=false → CPU (calibration decided not worth it)
    ├── Config: different device → GPU changed → auto-calibrate → overwrite config
    └── Config corrupted/unparseable → treat as no config → auto-calibrate
```

Integrated and discrete GPUs are treated identically. An integrated GPU is simply one that is always present. Calibration determines whether it is worth using — not a hardcoded assumption. An M4 GPU with unified memory and zero PCIe transfer cost may well win for SHA-256/MD5; an Intel UHD 630 probably will not. The config records the result either way.

### Calibration Config

Stored at platform-standard paths:
- Linux/Mac: `~/.config/blazehash/config.toml`
- Windows: `%APPDATA%\SecurityRonin\blazehash\config.toml`

```toml
[gpu]
device = "AMD Radeon RX 7600M XT"
calibrated = "2026-04-09"
threshold_single_mb = 48
threshold_multi_mb = 3
gpu_enabled = true
```

Config is **never deleted on GPU absence** — only overwritten on device name change or explicit `blazehash bench --gpu` run. This handles eGPU correctly: disconnect → config dormant → reconnect same device → thresholds immediately reused.

`--no-calibrate` flag: use conservative shipped defaults, no config written.

### GPU State Transitions

| Scenario | Behaviour |
|---|---|
| First run, no GPU | CPU, no config |
| First run, real GPU present | Auto-calibrate, write config |
| Same GPU, config valid | Use thresholds |
| Same GPU, calibration said no | CPU |
| GPU upgraded/swapped | Different device name → re-calibrate |
| eGPU disconnected | No adapter → CPU, config untouched |
| eGPU reconnected (same) | Same device → use existing config |
| eGPU swapped (different model) | Different device → re-calibrate |
| Integrated only, new discrete added | Different device → re-calibrate |
| GPU removed (any reason) | No adapter → CPU, config untouched |
| Driver update | Device name unchanged → existing config used (user re-runs bench manually if desired) |
| Config corrupted | Re-calibrate |
| `--no-calibrate` | Conservative defaults, no config |
| `blazehash bench --gpu` | Always calibrate, always overwrite config |

### Module Structure

```
src/gpu/
  mod.rs        — GpuHasher trait, adapter detection, threshold decision, config R/W
  backend.rs    — wgpu device/queue/buffer lifecycle
  sha256.wgsl   — WGSL compute shader: SHA-256
  md5.wgsl      — WGSL compute shader: MD5
```

Pipeline:
1. `GpuBackend::detect()` — returns `Option<GpuBackend>` (None = no usable GPU)
2. File bytes staged into GPU buffer via `wgpu::Queue::write_buffer`
3. Compute shader dispatched (one workgroup per 64 KB chunk)
4. Result read back via `wgpu::Buffer::map_async`
5. Result inserted into existing `HashResult` struct — downstream code (output, audit) is GPU-unaware

### Benchmark Calibration Tool

`blazehash bench --gpu` runs a matrix of file sizes × algorithm counts on both CPU and GPU, finds crossover points, writes config:

```
[*] Calibrating GPU vs CPU crossover on AMD Radeon RX 7600M XT...
    SHA-256, 1 algo:   CPU wins below 48 MB
    SHA-256, 3 algos:  CPU wins below 3 MB
    MD5, 1 algo:       CPU wins below 52 MB
[+] Calibration complete. Written to ~/.config/blazehash/config.toml
```

Also reports memory topology: `[*] Unified memory detected — thresholds will differ from discrete PCIe systems`

Benchmark hardware for shipped defaults: Paperspace RTX A5000 (PCIe 4.0, discrete, representative of self-built forensic workstation). Users with different hardware — especially Apple Silicon (unified memory, lower thresholds) or entry-level integrated GPUs — should run calibration.

### TDD

- Shader correctness: for every supported algorithm, GPU output == CPU output on 50+ vectors (empty input, single block, multi-block, exact boundary sizes)
- Threshold decision function tested independently of GPU hardware
- `GpuBackend::detect()` mockable — tests run on headless CI with no GPU
- State machine: all config transitions tested with temp config files
- `blazehash bench --gpu` integration tested against mock backend

---

## 3. Direct I/O (Cache Bypass)

### Purpose

Bypasses the OS page cache for direct disk reads. Forensic use case: hashing evidence on a live system without polluting the page cache. Small performance benefit on clean systems; meaningful on systems where cache pollution matters for chain of custody.

### Implementation

Exposed via `--no-cache` CLI flag. Platform implementations:

| Platform | Mechanism | Alignment requirement |
|---|---|---|
| Windows | `FILE_FLAG_NO_BUFFERING \| FILE_FLAG_SEQUENTIAL_SCAN` | Reads must be multiple of physical sector size (512 or 4096 bytes) |
| Linux | `O_DIRECT` | Same — `posix_memalign` for aligned read buffers |
| Mac | `fcntl(F_NOCACHE)` | No alignment requirement |

All alignment handling is internal to `src/io/` — transparent to callers.

### TDD

- Integration: hash known file with and without `--no-cache`, assert identical output
- Alignment unit tests: buffer alignment correct for sector sizes 512 and 4096
- Mac path tested on Mac CI; Windows/Linux paths on respective CI runners

---

## 4. Large Pages

### Purpose

Reduces TLB pressure when processing large files by using 2 MB pages for read buffers instead of 4 KB pages. Benefit is most visible on files > 1 GB with sequential access patterns.

### Implementation

| Platform | Mechanism | Privilege | Notes |
|---|---|---|---|
| Linux | `madvise(MADV_HUGEPAGE)` on mmap region | None required | Transparent huge pages; kernel decides |
| Windows | `VirtualAlloc` with `MEM_LARGE_PAGES` | `SeLockMemoryPrivilege` required | Silent fallback if privilege absent |
| Mac | Not available | N/A | No equivalent API |

Applied automatically (no flag) when files exceed 2 MB.

Windows privilege handling: attempt large page allocation; if it fails, fall back to normal pages silently. At `-v` verbosity: `[*] Large pages: enabled` or `[*] Large pages: unavailable (SeLockMemoryPrivilege not held)`.

### TDD

- Large page path: verify allocation succeeds on Linux (always) and Windows with privilege
- Fallback path: mock privilege failure on Windows, assert normal pages used, no error surfaced
- Output correctness: hash result identical with and without large pages

---

## Module Layout Summary

```
src/
  io/
    mod.rs          — FileReader trait, platform dispatch
    standard.rs     — rayon + mmap (Linux/Mac default)
    windows.rs      — tokio + IOCP + FILE_FLAG_NO_BUFFERING (Windows)
    linux.rs        — O_DIRECT + madvise HUGEPAGE (Linux)
    direct.rs       — --no-cache aligned buffer logic (cross-platform)
  gpu/
    mod.rs          — GpuHasher trait, detection, threshold, config
    backend.rs      — wgpu device/queue/buffer
    sha256.wgsl     — SHA-256 compute shader
    md5.wgsl        — MD5 compute shader
```

---

## Cargo Features Summary

```toml
[features]
default = ["forensic-image"]
forensic-image = ["dep:ewf"]
gpu = ["dep:wgpu", "dep:pollster"]
```

GPU is opt-in. All I/O improvements are always compiled (platform-gated via `#[cfg]`).

---

## Testing Strategy

All four features follow strict TDD:
1. RED commit: write failing tests that define behaviour
2. GREEN commit: minimal implementation to pass tests
3. Tests run on all three CI platforms (Ubuntu, macOS, Windows)
4. GPU tests gated behind `#[cfg(feature = "gpu")]`; mock backend used on headless CI
5. Platform-specific paths (IOCP, O_DIRECT, MEM_LARGE_PAGES) exercised on their respective CI runners

---

## Benchmark Reference Hardware

Shipped GPU threshold defaults calibrated on **Paperspace RTX A5000** (24 GB GDDR6, PCIe 4.0 discrete) — representative of a self-built forensic workstation with a high-end gaming/workstation card. Users with Apple Silicon, eGPUs, or integrated-only systems should run `blazehash bench --gpu` to obtain accurate thresholds for their hardware.
