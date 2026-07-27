#!/usr/bin/env python3
"""Generate publication-quality charts from benchmark results.json."""

import json
import math
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ── style ─────────────────────────────────────────────────────────────────────

BLUE   = "#2563EB"
ORANGE = "#EA580C"
GRAY   = "#6B7280"
GREEN  = "#16A34A"
RED    = "#DC2626"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "savefig.bbox": "tight",
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})

def errbar(ax, x, stat, color, label, width=0.35, offset=0):
    """Draw bar + 95% CI error bar."""
    ax.bar(x + offset, stat["mean"] * 1000, width, label=label,
           color=color, alpha=0.88, zorder=3)
    ax.errorbar(x + offset, stat["mean"] * 1000, yerr=stat["ci95_half"] * 1000,
                fmt="none", color="black", capsize=4, linewidth=1.2, zorder=4)

# ── chart 1: large file throughput (MB/s) across algorithms at 1 GiB ─────────

def chart_large_file_throughput(data, outdir):
    exp1 = data["exp1_large_file"]
    # Select 1024 MiB results
    rows_1g = {r["algo"]: r for r in exp1 if r["size_mb"] == 1024}

    algos_shared = ["sha256", "md5", "sha1"]
    bh_vals  = [rows_1g[a]["bh_throughput_mbs"]  for a in algos_shared]
    hd_vals  = [rows_1g[a]["hd_throughput_mbs"]  for a in algos_shared]
    bh_ci    = [rows_1g[a]["blazehash"]["ci95_half"] * 1024 / rows_1g[a]["blazehash"]["mean"] * rows_1g[a]["bh_throughput_mbs"]
                for a in algos_shared]
    hd_ci    = [rows_1g[a]["hashdeep"]["ci95_half"] * 1024 / rows_1g[a]["hashdeep"]["mean"] * rows_1g[a]["hd_throughput_mbs"]
                for a in algos_shared]

    # Add blake3 blazehash-only
    bh_b3    = rows_1g["blake3"]["bh_throughput_mbs"]
    bh_b3_ci = rows_1g["blake3"]["blazehash"]["ci95_half"] * 1024 / rows_1g["blake3"]["blazehash"]["mean"] * bh_b3

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(algos_shared))
    w = 0.35

    bars_bh = ax.bar(x - w/2, bh_vals, w, label="blazehash 0.2.2", color=BLUE, alpha=0.88, zorder=3)
    bars_hd = ax.bar(x + w/2, hd_vals, w, label="hashdeep 4.4",     color=ORANGE, alpha=0.88, zorder=3)
    ax.errorbar(x - w/2, bh_vals, yerr=bh_ci, fmt="none", color="black", capsize=4, linewidth=1.2, zorder=4)
    ax.errorbar(x + w/2, hd_vals, yerr=hd_ci, fmt="none", color="black", capsize=4, linewidth=1.2, zorder=4)

    # blake3 bar (single, no comparison)
    b3_x = len(algos_shared)
    ax.bar(b3_x, bh_b3, w, label="blazehash BLAKE3 (no hashdeep)", color=GREEN, alpha=0.88, zorder=3)
    ax.errorbar(b3_x, bh_b3, yerr=bh_b3_ci, fmt="none", color="black", capsize=4, linewidth=1.2, zorder=4)

    # speedup annotations
    for i, a in enumerate(algos_shared):
        sp = rows_1g[a]["speedup"]
        color = GREEN if sp > 1 else RED
        ax.text(i, max(bh_vals[i], hd_vals[i]) + 30, f"{sp:.2f}×",
                ha="center", fontsize=9, color=color, fontweight="bold")

    ax.set_xticks(list(range(len(algos_shared))) + [len(algos_shared)])
    ax.set_xticklabels([a.upper() for a in algos_shared] + ["BLAKE3"])
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_title("Single-File Throughput at 1 GiB — Warm Cache\n"
                 "Apple M4 Pro · macOS 15.7.5 · APFS NVMe")
    ax.legend(loc="upper left", fontsize=9)
    ax.set_ylim(0, max(bh_b3, max(hd_vals)) * 1.25)
    ax.yaxis.grid(True, alpha=0.3, zorder=0)
    ax.text(0.99, 0.97, "Error bars: 95% CI, n=7",
            transform=ax.transAxes, ha="right", va="top", fontsize=8, color=GRAY)

    fig.tight_layout()
    out = outdir / "fig1_throughput_1gib.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"  Written: {out}")

# ── chart 2: throughput scaling with file size (sha256) ───────────────────────

def chart_throughput_scaling(data, outdir):
    exp1 = data["exp1_large_file"]
    sizes = sorted(set(r["size_mb"] for r in exp1))
    sha256 = {r["size_mb"]: r for r in exp1 if r["algo"] == "sha256"}
    blake3 = {r["size_mb"]: r for r in exp1 if r["algo"] == "blake3"}

    bh_sha = [sha256[s]["bh_throughput_mbs"] for s in sizes]
    hd_sha = [sha256[s]["hd_throughput_mbs"] for s in sizes]
    bh_b3  = [blake3[s]["bh_throughput_mbs"] for s in sizes]
    bh_sha_err = [sha256[s]["blazehash"]["ci95_half"]/sha256[s]["blazehash"]["mean"]*sha256[s]["bh_throughput_mbs"] for s in sizes]
    hd_sha_err = [sha256[s]["hashdeep"]["ci95_half"]/sha256[s]["hashdeep"]["mean"]*sha256[s]["hd_throughput_mbs"] for s in sizes]
    bh_b3_err  = [blake3[s]["blazehash"]["ci95_half"]/blake3[s]["blazehash"]["mean"]*blake3[s]["bh_throughput_mbs"] for s in sizes]

    size_labels = [f"{s} MiB" for s in sizes]

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(sizes))
    ax.plot(x, bh_sha, "o-", color=BLUE,   label="blazehash SHA-256", linewidth=2, markersize=7, zorder=3)
    ax.plot(x, hd_sha, "s-", color=ORANGE, label="hashdeep SHA-256",  linewidth=2, markersize=7, zorder=3)
    ax.plot(x, bh_b3,  "^-", color=GREEN,  label="blazehash BLAKE3",  linewidth=2, markersize=7, zorder=3, linestyle="--")
    ax.fill_between(x, [v-e for v,e in zip(bh_sha,bh_sha_err)],
                       [v+e for v,e in zip(bh_sha,bh_sha_err)], color=BLUE, alpha=0.12)
    ax.fill_between(x, [v-e for v,e in zip(hd_sha,hd_sha_err)],
                       [v+e for v,e in zip(hd_sha,hd_sha_err)], color=ORANGE, alpha=0.12)
    ax.fill_between(x, [v-e for v,e in zip(bh_b3,bh_b3_err)],
                       [v+e for v,e in zip(bh_b3,bh_b3_err)], color=GREEN, alpha=0.12)

    ax.set_xticks(x)
    ax.set_xticklabels(size_labels)
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_title("Throughput vs File Size — SHA-256 and BLAKE3\n"
                 "Shaded: 95% CI, n=7 warm-cache runs each")
    ax.legend(loc="lower right", fontsize=9)
    ax.yaxis.grid(True, alpha=0.3, zorder=0)
    ax.set_ylim(0, max(bh_b3) * 1.25)
    ax.text(0.01, 0.97, "BLAKE3 unavailable in hashdeep 4.4",
            transform=ax.transAxes, ha="left", va="top", fontsize=8, color=GRAY, style="italic")

    fig.tight_layout()
    out = outdir / "fig2_throughput_scaling.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"  Written: {out}")

# ── chart 3: many small files — per-file latency ──────────────────────────────

def chart_small_files(data, outdir):
    exp2 = data["exp2_many_files"]
    counts = [r["count"] for r in exp2]
    bh_lat = [r["bh_per_file_us"] for r in exp2]
    hd_lat = [r["hd_per_file_us"] for r in exp2]
    bh_ci  = [r["blazehash"]["ci95_half"]/r["blazehash"]["mean"]*r["bh_per_file_us"] for r in exp2]
    hd_ci  = [r["hashdeep"]["ci95_half"]/r["hashdeep"]["mean"]*r["hd_per_file_us"] for r in exp2]
    speedups = [r["speedup"] for r in exp2]

    x = np.arange(len(counts))
    w = 0.35

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Left: per-file latency
    ax1.bar(x - w/2, bh_lat, w, label="blazehash", color=BLUE, alpha=0.88, zorder=3)
    ax1.bar(x + w/2, hd_lat, w, label="hashdeep",  color=ORANGE, alpha=0.88, zorder=3)
    ax1.errorbar(x - w/2, bh_lat, yerr=bh_ci, fmt="none", color="black", capsize=3, linewidth=1, zorder=4)
    ax1.errorbar(x + w/2, hd_lat, yerr=hd_ci, fmt="none", color="black", capsize=3, linewidth=1, zorder=4)
    ax1.set_xticks(x)
    ax1.set_xticklabels([f"{c:,}" for c in counts])
    ax1.set_xlabel("Number of files (2 KiB each, SHA-256)")
    ax1.set_ylabel("Per-file latency (µs)")
    ax1.set_title("Per-File Processing Latency\nvs File Count")
    ax1.legend(fontsize=9)
    ax1.yaxis.grid(True, alpha=0.3, zorder=0)

    # Right: speedup
    colors = [GREEN if s > 1 else RED for s in speedups]
    ax2.bar(x, speedups, 0.5, color=colors, alpha=0.88, zorder=3)
    ax2.axhline(1.0, color="black", linewidth=1, linestyle="--", zorder=2)
    ax2.set_xticks(x)
    ax2.set_xticklabels([f"{c:,}" for c in counts])
    ax2.set_xlabel("Number of files")
    ax2.set_ylabel("Speedup (blazehash / hashdeep, >1 = blazehash faster)")
    ax2.set_title("Relative Speed\n(blazehash ÷ hashdeep wall-clock time)")
    ax2.yaxis.grid(True, alpha=0.3, zorder=0)
    for i, s in enumerate(speedups):
        label = f"{s:.2f}×"
        color = GREEN if s > 1 else RED
        ax2.text(i, s + 0.02, label, ha="center", fontsize=9, color=color, fontweight="bold")

    green_patch = mpatches.Patch(color=GREEN, label="blazehash faster")
    red_patch   = mpatches.Patch(color=RED,   label="hashdeep faster")
    ax2.legend(handles=[green_patch, red_patch], fontsize=9)

    fig.suptitle("Many Small Files Benchmark — 2 KiB × N, SHA-256, Warm Cache\n"
                 "Apple M4 Pro · n=5 runs · 95% CI", fontsize=12, fontweight="bold")
    fig.tight_layout()
    out = outdir / "fig3_small_files.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"  Written: {out}")

# ── chart 4: algorithm comparison at 1 GiB (all algos, blazehash) ────────────

def chart_algo_comparison(data, outdir):
    exp1 = data["exp1_large_file"]
    rows_1g = {r["algo"]: r for r in exp1 if r["size_mb"] == 1024}

    algos = ["blake3", "sha1", "md5", "sha256"]
    labels = ["BLAKE3\n(bh only)", "SHA-1", "MD5", "SHA-256"]
    bh_tputs = [rows_1g[a]["bh_throughput_mbs"] for a in algos]
    hd_tputs = [rows_1g[a]["hd_throughput_mbs"] if rows_1g[a]["hd_throughput_mbs"] else 0
                for a in algos]
    speedups = [rows_1g[a]["speedup"] if rows_1g[a]["speedup"] else None for a in algos]

    x = np.arange(len(algos))
    w = 0.35

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - w/2, bh_tputs, w, label="blazehash 0.2.2", color=BLUE, alpha=0.88, zorder=3)
    hd_bars = ax.bar(x + w/2, hd_tputs, w, label="hashdeep 4.4",     color=ORANGE, alpha=0.88, zorder=3)
    # Mark BLAKE3 hashdeep bar as N/A
    ax.text(len(algos)-len(algos) + w/2, 20, "N/A", ha="center", fontsize=8, color=GRAY)

    for i, sp in enumerate(speedups):
        if sp is not None:
            color = GREEN if sp > 1 else RED
            ax.text(i, max(bh_tputs[i], hd_tputs[i]) + 30, f"{sp:.2f}×",
                    ha="center", fontsize=9, color=color, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_title("Per-Algorithm Throughput at 1 GiB — Warm Cache\n"
                 "Annotation: blazehash speedup over hashdeep")
    ax.legend(fontsize=9)
    ax.yaxis.grid(True, alpha=0.3, zorder=0)
    ax.set_ylim(0, max(bh_tputs) * 1.25)
    ax.text(0.99, 0.97, "SHA-1 speedup from ARM NEON hardware extensions\n(sha1c/sha1p/sha1m on M4 Pro)",
            transform=ax.transAxes, ha="right", va="top", fontsize=8, color=GRAY, style="italic")

    fig.tight_layout()
    out = outdir / "fig4_algo_comparison_1gib.png"
    fig.savefig(out)
    plt.close(fig)
    print(f"  Written: {out}")

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    results_path = Path("docs/bench/results.json")
    if not results_path.exists():
        sys.exit(f"ERROR: {results_path} not found. Run run_benchmarks.py first.")

    with open(results_path) as f:
        data = json.load(f)

    outdir = Path("docs/charts")
    outdir.mkdir(parents=True, exist_ok=True)

    print("[*] Generating charts...")
    chart_large_file_throughput(data, outdir)
    chart_throughput_scaling(data, outdir)
    chart_small_files(data, outdir)
    chart_algo_comparison(data, outdir)
    print(f"[+] All charts written to {outdir}/")

if __name__ == "__main__":
    main()
