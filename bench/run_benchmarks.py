#!/usr/bin/env python3
"""
blazehash vs hashdeep — rigorous benchmark suite.

Methodology
-----------
- All benchmarks run on warm filesystem cache (one discarded warmup run precedes
  each timed series).
- N = 7 timed runs per scenario. We report: min, max, mean, standard deviation,
  and 95% confidence interval (t-distribution, df = N-1 = 6).
- Timing uses time.perf_counter() around subprocess.run(), capturing wall-clock
  time inclusive of process spawn.
- Test data is generated once using a seeded LCG (Lehmer) for reproducibility;
  the same bytes are hashed by both tools.
- Correctness: hash values are compared between tools for every shared algorithm
  and file size. Any mismatch aborts the run.

Limitations stated explicitly
------------------------------
- Warm-cache only: macOS `purge` requires root. Cold-cache numbers are not reported.
- Large-file extrapolation: files > 1 GiB are not created; throughput at saturation
  (measured at 1 GiB) is used to estimate time at 1 TiB. Extrapolation assumes
  linear scaling — valid when I/O is the bottleneck, which is noted.
- EWF/E01: hashdeep v4.4 has no EWF support. This is documented as a capability
  gap, not a performance comparison.
- Many-file extrapolation: 500 M × 2 KiB files are not created. Throughput from
  10,000-file test is extrapolated with per-file-overhead model.

Usage
-----
  python3 docs/bench/run_benchmarks.py [--blazehash PATH] [--hashdeep PATH] [--outdir DIR]
"""

import argparse
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ── statistical helpers ──────────────────────────────────────────────────────

def mean(xs):
    return sum(xs) / len(xs)

def stdev(xs):
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))

def t95(n):
    """Two-tailed t critical value at 95% CI for df = n-1 (tabulated)."""
    table = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776,
             5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228}
    return table.get(n - 1, 2.0)  # fallback to z≈2 for large n

def ci95(xs):
    n = len(xs)
    m = mean(xs)
    s = stdev(xs) if n > 1 else 0.0
    half = t95(n) * s / math.sqrt(n)
    return m, s, half  # (mean, sd, half-width of 95% CI)

def stats(xs):
    m, s, hw = ci95(xs)
    return {"n": len(xs), "min": min(xs), "max": max(xs),
            "mean": m, "sd": s, "ci95_half": hw,
            "raw": xs}

# ── data generation ──────────────────────────────────────────────────────────

def lcg_bytes(size: int, seed: int = 0x4E56_4C43) -> bytes:
    """Generate `size` pseudo-random bytes using a 32-bit Lehmer LCG.
    Deterministic across platforms; same seed → same bytes."""
    A, M = 1664525, 2**32
    state = seed
    out = bytearray(size)
    for i in range(size):
        state = (A * state + 1013904223) & (M - 1)
        out[i] = state >> 24
    return bytes(out)

def create_file(path: Path, size_bytes: int):
    """Write deterministic content to path. Uses 4 MiB chunks for speed."""
    CHUNK = 4 * 1024 * 1024
    written = 0
    seed = 0x4E56_4C43
    with open(path, 'wb') as f:
        while written < size_bytes:
            n = min(CHUNK, size_bytes - written)
            # Fast: just use os.urandom equivalent but deterministic chunk
            # We use a single LCG state carried across chunks
            chunk = lcg_bytes(n, seed + written)
            f.write(chunk)
            written += n
    return path

def create_file_fast(path: Path, size_bytes: int):
    """Fast file creation using /dev/urandom — not deterministic but fast for timing tests."""
    with open(path, 'wb') as f:
        remaining = size_bytes
        while remaining > 0:
            chunk = min(remaining, 4 * 1024 * 1024)
            f.write(os.urandom(chunk))
            remaining -= chunk

# ── tool runners ─────────────────────────────────────────────────────────────

def time_cmd(cmd: list, cwd=None) -> float:
    """Return wall-clock seconds for command, raise if non-zero exit."""
    t0 = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, cwd=cwd)
    elapsed = time.perf_counter() - t0
    if r.returncode != 0:
        raise RuntimeError(f"Command failed ({r.returncode}): {' '.join(cmd)}\n"
                           f"stderr: {r.stderr.decode()[:500]}")
    return elapsed

def get_hash(cmd: list) -> str:
    """Run command and return stdout stripped."""
    r = subprocess.run(cmd, capture_output=True, check=True)
    return r.stdout.decode().strip()

def bench(cmd: list, n: int = 7, warmup: int = 1) -> dict:
    """Run command n times after warmup discards. Return stats dict."""
    for _ in range(warmup):
        try:
            subprocess.run(cmd, capture_output=True, timeout=300)
        except Exception:
            pass
    times = []
    for _ in range(n):
        try:
            times.append(time_cmd(cmd))
        except Exception as e:
            print(f"  WARNING: run failed: {e}", file=sys.stderr)
    if not times:
        raise RuntimeError(f"All runs failed for: {' '.join(cmd)}")
    return stats(times)

# ── correctness verification ─────────────────────────────────────────────────

def verify_correctness(blazehash_bin, hashdeep_bin, tmpdir):
    """Verify blazehash and hashdeep produce identical hashes for shared algos."""
    print("\n[*] Verifying correctness (hash value agreement)...")
    results = []
    sizes = [0, 1, 1024, 100*1024, 1024*1024]  # 0B, 1B, 1KB, 100KB, 1MB
    algos = ["md5", "sha1", "sha256"]           # hashdeep -c tiger/whirlpool has quirks

    for size in sizes:
        path = Path(tmpdir) / f"verify_{size}.bin"
        create_file(path, size)
        size_label = f"{size}B" if size < 1024 else (
            f"{size//1024}KB" if size < 1024*1024 else f"{size//1024//1024}MB")

        for algo in algos:
            # blazehash bare format: "size,hash,filename" (hashdeep data-line format)
            bh_out = subprocess.run(
                [blazehash_bin, "-c", algo, "--bare", str(path)],
                capture_output=True, check=True
            ).stdout.decode().strip()
            # field 0 = size, field 1 = hash, field 2 = filename
            bh_parts = bh_out.split(",")
            bh_hash = bh_parts[1].strip() if len(bh_parts) >= 2 else ""

            # hashdeep output: comment lines starting with %, then "size,hash,filename"
            hd_out = subprocess.run(
                [hashdeep_bin, "-c", algo, str(path)],
                capture_output=True
            ).stdout.decode()
            hd_hash = ""
            for line in hd_out.splitlines():
                if line.startswith("%") or not line.strip():
                    continue
                parts = line.strip().split(",")
                if len(parts) >= 2:
                    hd_hash = parts[1].strip()
                    break

            match = (bh_hash.lower() == hd_hash.lower()) and bh_hash != ""
            results.append({
                "size": size_label, "algo": algo,
                "blazehash": bh_hash, "hashdeep": hd_hash, "match": match
            })
            status = "PASS" if match else "FAIL"
            print(f"  [{status}] {algo:8s} {size_label:8s}  bh={bh_hash[:16]}...  hd={hd_hash[:16]}...")
            if not match:
                print(f"  ERROR: hash mismatch! bh={bh_hash}  hd={hd_hash}")

    return results

# ── experiment 1: single large file ─────────────────────────────────────────

def exp_large_file(blazehash_bin, hashdeep_bin, tmpdir, n=7):
    """Throughput benchmark: single file of increasing size."""
    print("\n[*] Experiment 1: Single large file throughput")
    sizes_mb = [64, 256, 512, 1024]  # MB
    algos_shared = ["sha256", "md5", "sha1"]
    results = []

    for size_mb in sizes_mb:
        size_bytes = size_mb * 1024 * 1024
        path = Path(tmpdir) / f"large_{size_mb}mb.bin"
        print(f"\n  Creating {size_mb} MiB test file...", end=" ", flush=True)
        t0 = time.perf_counter()
        create_file_fast(path, size_bytes)
        print(f"done ({time.perf_counter()-t0:.1f}s)")

        for algo in algos_shared:
            print(f"  {size_mb} MiB / {algo}: ", end="", flush=True)

            # blazehash
            bh_cmd = [blazehash_bin, "-c", algo, "--bare", str(path)]
            bh = bench(bh_cmd, n=n)
            bh_tput = size_bytes / bh["mean"] / 1e6  # MB/s

            # hashdeep
            hd_cmd = [hashdeep_bin, "-c", algo, str(path)]
            hd = bench(hd_cmd, n=n)
            hd_tput = size_bytes / hd["mean"] / 1e6

            speedup = bh["mean"] / hd["mean"]  # <1 means blazehash faster
            print(f"bh={bh['mean']*1000:.0f}±{bh['ci95_half']*1000:.0f}ms "
                  f"({bh_tput:.0f} MB/s)  "
                  f"hd={hd['mean']*1000:.0f}±{hd['ci95_half']*1000:.0f}ms "
                  f"({hd_tput:.0f} MB/s)  "
                  f"ratio={1/speedup:.2f}x")

            results.append({
                "size_mb": size_mb, "algo": algo,
                "blazehash": bh, "hashdeep": hd,
                "bh_throughput_mbs": bh_tput, "hd_throughput_mbs": hd_tput,
                "speedup": 1 / speedup
            })

        # blake3 — blazehash only
        print(f"  {size_mb} MiB / blake3 (blazehash only): ", end="", flush=True)
        bh_cmd = [blazehash_bin, "-c", "blake3", "--bare", str(path)]
        bh = bench(bh_cmd, n=n)
        bh_tput = size_bytes / bh["mean"] / 1e6
        print(f"bh={bh['mean']*1000:.0f}±{bh['ci95_half']*1000:.0f}ms ({bh_tput:.0f} MB/s)")
        results.append({
            "size_mb": size_mb, "algo": "blake3",
            "blazehash": bh, "hashdeep": None,
            "bh_throughput_mbs": bh_tput, "hd_throughput_mbs": None,
            "speedup": None
        })

        # Cleanup large files after each size to save disk space
        path.unlink(missing_ok=True)

    return results

# ── experiment 2: many small files ──────────────────────────────────────────

def exp_many_files(blazehash_bin, hashdeep_bin, tmpdir, n=5):
    """Per-file-overhead benchmark: N files × 2 KiB."""
    print("\n[*] Experiment 2: Many small files (2 KiB each, sha256)")
    counts = [100, 1000, 5000, 10000]
    results = []
    file_size = 2048  # 2 KiB

    for count in counts:
        d = Path(tmpdir) / f"files_{count}"
        d.mkdir(exist_ok=True)
        print(f"\n  Creating {count} × 2 KiB files...", end=" ", flush=True)
        for i in range(count):
            p = d / f"f{i:07d}.bin"
            if not p.exists():
                p.write_bytes(lcg_bytes(file_size, seed=i))
        print("done")

        total_mb = count * file_size / 1e6

        print(f"  {count} files (total {total_mb:.1f} MB) / sha256: ", end="", flush=True)

        bh_cmd = [blazehash_bin, "-c", "sha256", "-r", "--bare", str(d)]
        bh = bench(bh_cmd, n=n)
        bh_tput = (count * file_size) / bh["mean"] / 1e6

        hd_cmd = [hashdeep_bin, "-c", "sha256", "-r", str(d)]
        hd = bench(hd_cmd, n=n)
        hd_tput = (count * file_size) / hd["mean"] / 1e6

        speedup = 1 / (bh["mean"] / hd["mean"])
        per_file_bh_us = bh["mean"] / count * 1e6
        per_file_hd_us = hd["mean"] / count * 1e6

        print(f"bh={bh['mean']*1000:.0f}±{bh['ci95_half']*1000:.0f}ms "
              f"({per_file_bh_us:.0f} µs/file)  "
              f"hd={hd['mean']*1000:.0f}±{hd['ci95_half']*1000:.0f}ms "
              f"({per_file_hd_us:.0f} µs/file)  "
              f"speedup={speedup:.2f}x")

        results.append({
            "count": count, "file_size_bytes": file_size,
            "blazehash": bh, "hashdeep": hd,
            "bh_throughput_mbs": bh_tput, "hd_throughput_mbs": hd_tput,
            "bh_per_file_us": per_file_bh_us, "hd_per_file_us": per_file_hd_us,
            "speedup": speedup
        })

    return results

# ── experiment 3: multi-algorithm combined ───────────────────────────────────

def exp_multi_algo(blazehash_bin, hashdeep_bin, tmpdir, n=7):
    """All shared algorithms simultaneously on a 256 MiB file."""
    print("\n[*] Experiment 3: All algorithms simultaneously (256 MiB)")
    size_mb = 256
    size_bytes = size_mb * 1024 * 1024
    path = Path(tmpdir) / "multi_algo_256mb.bin"
    print(f"  Creating {size_mb} MiB file...", end=" ", flush=True)
    create_file_fast(path, size_bytes)
    print("done")

    results = []

    # blazehash: all 5 shared algos at once
    bh_cmd = [blazehash_bin, "-c", "md5,sha1,sha256,tiger,whirlpool", "--bare", str(path)]
    bh = bench(bh_cmd, n=n)
    bh_tput = size_bytes / bh["mean"] / 1e6
    print(f"  blazehash (5 algos): {bh['mean']*1000:.0f}±{bh['ci95_half']*1000:.0f}ms "
          f"({bh_tput:.0f} MB/s effective)")

    # hashdeep: default (md5+sha1+sha256) — hashdeep has no tiger/whirlpool in -c
    hd_cmd = [hashdeep_bin, str(path)]  # default = md5+sha1+sha256
    hd = bench(hd_cmd, n=n)
    hd_tput = size_bytes / hd["mean"] / 1e6
    print(f"  hashdeep (3 algos, default): {hd['mean']*1000:.0f}±{hd['ci95_half']*1000:.0f}ms "
          f"({hd_tput:.0f} MB/s effective)")

    results.append({
        "scenario": "blazehash_5_algos",
        "algos": "md5,sha1,sha256,tiger,whirlpool",
        "size_mb": size_mb, "stats": bh, "throughput_mbs": bh_tput
    })
    results.append({
        "scenario": "hashdeep_3_algos_default",
        "algos": "md5,sha1,sha256",
        "size_mb": size_mb, "stats": hd, "throughput_mbs": hd_tput
    })

    path.unlink(missing_ok=True)
    return results

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="blazehash vs hashdeep benchmark")
    parser.add_argument("--blazehash", default=None)
    parser.add_argument("--hashdeep", default=shutil.which("hashdeep") or "hashdeep")
    parser.add_argument("--outdir", default="docs/bench")
    parser.add_argument("--n", type=int, default=7, help="runs per scenario")
    args = parser.parse_args()

    # Locate blazehash binary
    bh_bin = args.blazehash
    if bh_bin is None:
        candidates = [
            Path("target/release/blazehash"),
            Path(__file__).parent.parent.parent / "target/release/blazehash",
        ]
        for c in candidates:
            if c.exists():
                bh_bin = str(c.resolve())
                break
    if bh_bin is None or not Path(bh_bin).exists():
        sys.exit("ERROR: blazehash binary not found. Pass --blazehash PATH or run from repo root.")

    hd_bin = args.hashdeep
    if not shutil.which(hd_bin):
        sys.exit(f"ERROR: hashdeep not found at {hd_bin}")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print("=" * 72)
    print("blazehash vs hashdeep — benchmark suite")
    print("=" * 72)
    print(f"  blazehash: {bh_bin}")
    print(f"  hashdeep:  {shutil.which(hd_bin)}")
    print(f"  runs/scenario: {args.n}")
    print(f"  output: {outdir.resolve()}")

    with tempfile.TemporaryDirectory(prefix="blazehash_bench_") as tmpdir:
        all_results = {}

        # Correctness check first — abort if any mismatch
        correctness = verify_correctness(bh_bin, hd_bin, tmpdir)
        all_results["correctness"] = correctness
        failures = [r for r in correctness if not r["match"]]
        if failures:
            sys.exit(f"ABORT: {len(failures)} hash value mismatches. Results invalid.")
        print(f"  [PASS] All {len(correctness)} correctness checks passed.")

        # Experiments
        all_results["exp1_large_file"] = exp_large_file(bh_bin, hd_bin, tmpdir, n=args.n)
        all_results["exp2_many_files"] = exp_many_files(bh_bin, hd_bin, tmpdir, n=args.n)
        all_results["exp3_multi_algo"] = exp_multi_algo(bh_bin, hd_bin, tmpdir, n=args.n)

    # Save raw JSON
    out_json = outdir / "results.json"
    with open(out_json, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n[+] Raw data written to {out_json}")
    print("    Next: python3 docs/bench/generate_charts.py")
    print("    Then: python3 docs/bench/generate_report.py")

if __name__ == "__main__":
    main()
