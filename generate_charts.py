#!/usr/bin/env python3
"""Generate academic-style benchmark charts for blazehash documentation.

Usage:
    python3 docs/generate_charts.py

Outputs PNG files to docs/charts/. These are committed to the repo and
referenced from docs/benchmarks.md.
"""

import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

# ---------------------------------------------------------------------------
# Style — academic paper conventions
# ---------------------------------------------------------------------------
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "axes.grid.axis": "y",
    "grid.alpha": 0.3,
    "grid.linestyle": "--",
})

HASHDEEP_COLOR = "#5B7BA5"  # steel blue
BLAZEHASH_COLOR = "#D96459"  # terra cotta
HASHDEEP_HATCH = "///"
BLAZEHASH_HATCH = ""
BAR_EDGECOLOR = "black"
BAR_LINEWIDTH = 0.6

OUTDIR = os.path.join(os.path.dirname(__file__), "charts")
os.makedirs(OUTDIR, exist_ok=True)


def save(fig, name):
    path = os.path.join(OUTDIR, name)
    fig.savefig(path, facecolor="white")
    plt.close(fig)
    print(f"  {path}")


def add_value_labels(ax, bars, fmt="{:.0f}"):
    """Add value labels above each bar."""
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                h,
                fmt.format(h),
                ha="center",
                va="bottom",
                fontsize=8,
                color="#333333",
            )


def grouped_bar(ax, labels, hd_vals, bh_vals, ylabel, title):
    """Draw a grouped bar chart — hashdeep vs blazehash."""
    x = np.arange(len(labels))
    width = 0.35

    bars_hd = ax.bar(
        x - width / 2, hd_vals, width,
        label="hashdeep v4.4",
        color=HASHDEEP_COLOR, hatch=HASHDEEP_HATCH,
        edgecolor=BAR_EDGECOLOR, linewidth=BAR_LINEWIDTH,
    )
    bars_bh = ax.bar(
        x + width / 2, bh_vals, width,
        label="blazehash",
        color=BLAZEHASH_COLOR, hatch=BLAZEHASH_HATCH,
        edgecolor=BAR_EDGECOLOR, linewidth=BAR_LINEWIDTH,
    )

    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend(frameon=True, framealpha=0.9, edgecolor="#cccccc")
    ax.set_ylim(bottom=0)

    add_value_labels(ax, bars_hd)
    add_value_labels(ax, bars_bh)


def add_speedup_annotations(ax, labels, hd_vals, bh_vals):
    """Add speedup annotations (e.g. '2.08x') between bar pairs."""
    x = np.arange(len(labels))
    width = 0.35
    for i in range(len(labels)):
        if hd_vals[i] > 0 and bh_vals[i] > 0:
            speedup = hd_vals[i] / bh_vals[i]
            # Place annotation above the taller bar
            y = max(hd_vals[i], bh_vals[i])
            ax.annotate(
                f"{speedup:.1f}x",
                xy=(x[i], y),
                xytext=(0, 18),
                textcoords="offset points",
                ha="center", va="bottom",
                fontsize=8, fontweight="bold",
                color="#2a7f2a",
            )


# ---------------------------------------------------------------------------
# Chart 1: Large File Throughput (256 MiB)
# ---------------------------------------------------------------------------
def chart_large_file():
    labels = ["MD5", "SHA-1", "SHA-256", "Tiger", "Whirlpool", "All 5"]
    hd = [678, 572, 930, 968, 1206, 3521]
    bh = [587, 275, 854, 692, 1117, 3092]

    fig, ax = plt.subplots(figsize=(7, 4))
    grouped_bar(ax, labels, hd, bh,
                ylabel="Time (ms)",
                title="256 MiB Single File — Time (lower is better)")
    add_speedup_annotations(ax, labels, hd, bh)
    # Increase top margin for annotations
    ymax = max(max(hd), max(bh))
    ax.set_ylim(0, ymax * 1.25)
    fig.tight_layout()
    save(fig, "large_file.png")


# ---------------------------------------------------------------------------
# Chart 2: Many Small Files (1000 x 4 KiB)
# ---------------------------------------------------------------------------
def chart_small_files():
    labels = ["SHA-256", "All 5 algorithms"]
    hd = [69, 76]
    bh = [20, 28]

    fig, ax = plt.subplots(figsize=(4.5, 4))
    grouped_bar(ax, labels, hd, bh,
                ylabel="Time (ms)",
                title="1,000 Small Files (4 KiB each)")
    add_speedup_annotations(ax, labels, hd, bh)
    ymax = max(max(hd), max(bh))
    ax.set_ylim(0, ymax * 1.3)
    fig.tight_layout()
    save(fig, "small_files.png")


# ---------------------------------------------------------------------------
# Chart 3: Recursive Directory Walk (500 files)
# ---------------------------------------------------------------------------
def chart_recursive():
    labels = ["SHA-256", "All 5 algorithms"]
    hd = [45, 47]
    bh = [27, 28]

    fig, ax = plt.subplots(figsize=(4.5, 4))
    grouped_bar(ax, labels, hd, bh,
                ylabel="Time (ms)",
                title="Recursive Walk — 500 Files, 8 MiB")
    add_speedup_annotations(ax, labels, hd, bh)
    ymax = max(max(hd), max(bh))
    ax.set_ylim(0, ymax * 1.3)
    fig.tight_layout()
    save(fig, "recursive_walk.png")


# ---------------------------------------------------------------------------
# Chart 4: Piecewise Hashing (64 MiB, 1M chunks)
# ---------------------------------------------------------------------------
def chart_piecewise():
    labels = ["SHA-256", "All 5 algorithms"]
    hd = [339, 1775]
    bh = [163, 825]

    fig, ax = plt.subplots(figsize=(4.5, 4))
    grouped_bar(ax, labels, hd, bh,
                ylabel="Time (ms)",
                title="Piecewise Hashing — 64 MiB, 1M Chunks")
    add_speedup_annotations(ax, labels, hd, bh)
    ymax = max(max(hd), max(bh))
    ax.set_ylim(0, ymax * 1.2)
    fig.tight_layout()
    save(fig, "piecewise.png")


# ---------------------------------------------------------------------------
# Chart 5: BLAKE3 Advantage — all algorithms
# ---------------------------------------------------------------------------
def chart_blake3():
    # Sorted by blazehash time (fastest first).
    # hashdeep value is 0 where unsupported.
    labels = [
        "BLAKE3", "SHA-1", "SHA3-256", "Tiger",
        "SHA-512", "MD5", "SHA-256", "Whirlpool",
    ]
    bh = [187, 275, 376, 388, 407, 419, 672, 808]
    hd = [0,   572, 0,   968, 0,   678, 930, 1206]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 4.5))

    # Draw hashdeep bars only where supported
    hd_x = []
    hd_h = []
    hd_pos = []
    for i in range(len(labels)):
        if hd[i] > 0:
            hd_x.append(x[i] - width / 2)
            hd_h.append(hd[i])
            hd_pos.append(i)

    bars_hd = ax.bar(
        hd_x, hd_h, width,
        color=HASHDEEP_COLOR, hatch=HASHDEEP_HATCH,
        edgecolor=BAR_EDGECOLOR, linewidth=BAR_LINEWIDTH,
    )

    # blazehash bars — shift right only where hashdeep is present,
    # center where blazehash-only
    bh_positions = []
    for i in range(len(labels)):
        if hd[i] > 0:
            bh_positions.append(x[i] + width / 2)
        else:
            bh_positions.append(x[i])

    bars_bh = ax.bar(
        bh_positions, bh, width,
        color=BLAZEHASH_COLOR, hatch=BLAZEHASH_HATCH,
        edgecolor=BAR_EDGECOLOR, linewidth=BAR_LINEWIDTH,
    )

    # Value labels
    add_value_labels(ax, bars_hd)
    add_value_labels(ax, bars_bh)

    # Speedup annotations for shared algorithms
    for i in range(len(labels)):
        if hd[i] > 0:
            speedup = hd[i] / bh[i]
            y = max(hd[i], bh[i])
            ax.annotate(
                f"{speedup:.1f}x",
                xy=(x[i], y),
                xytext=(0, 18),
                textcoords="offset points",
                ha="center", va="bottom",
                fontsize=8, fontweight="bold",
                color="#2a7f2a",
            )

    # Mark blazehash-only algorithms
    for i in range(len(labels)):
        if hd[i] == 0:
            ax.annotate(
                "blazehash only",
                xy=(x[i], bh[i]),
                xytext=(0, 6),
                textcoords="offset points",
                ha="center", va="bottom",
                fontsize=7, fontstyle="italic",
                color="#666666",
            )

    ax.set_ylabel("Time (ms)")
    ax.set_title("256 MiB — All Algorithms (lower is better)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)

    # Manual legend
    legend_elements = [
        Patch(facecolor=HASHDEEP_COLOR, edgecolor=BAR_EDGECOLOR,
              hatch=HASHDEEP_HATCH, linewidth=BAR_LINEWIDTH,
              label="hashdeep v4.4"),
        Patch(facecolor=BLAZEHASH_COLOR, edgecolor=BAR_EDGECOLOR,
              hatch=BLAZEHASH_HATCH, linewidth=BAR_LINEWIDTH,
              label="blazehash"),
    ]
    ax.legend(handles=legend_elements, frameon=True, framealpha=0.9,
              edgecolor="#cccccc")

    ymax = max(max(hd), max(bh))
    ax.set_ylim(0, ymax * 1.22)
    fig.tight_layout()
    save(fig, "blake3_advantage.png")


# ---------------------------------------------------------------------------
# Chart 6: Throughput (MB/s) — large file
# ---------------------------------------------------------------------------
def chart_throughput():
    labels = ["MD5", "SHA-1", "SHA-256", "Tiger", "Whirlpool"]
    hd = [378, 448, 275, 264, 212]
    bh = [436, 932, 300, 370, 229]

    fig, ax = plt.subplots(figsize=(6.5, 4))
    grouped_bar(ax, labels, hd, bh,
                ylabel="Throughput (MB/s)",
                title="256 MiB Single File — Throughput (higher is better)")
    ymax = max(max(hd), max(bh))
    ax.set_ylim(0, ymax * 1.15)
    fig.tight_layout()
    save(fig, "throughput.png")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Generating benchmark charts...")
    chart_large_file()
    chart_small_files()
    chart_recursive()
    chart_piecewise()
    chart_blake3()
    chart_throughput()
    print("Done.")
