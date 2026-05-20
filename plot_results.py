#!/usr/bin/env python3
"""
plot_results.py  —  Student tool

Reads your results/*.csv files and saves standard charts to plots/.
Run this script after completing each phase to visualise your data.

Usage
-----
    python plot_results.py              # generate all available charts
    python plot_results.py --phase 1    # phase 1 chart only
    python plot_results.py --phase 2
    python plot_results.py --phase 3

Output
------
    plots/phase1_growth.png      crack time vs password length  (Phase 1)
    plots/phase2_comparison.png  brute-force vs dictionary       (Phase 2)
    plots/phase3_hybrid.png      hybrid rule comparison          (Phase 3)
    plots/summary.png            all three phases side by side
"""

import argparse
import csv
import os
import sys

try:
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    from matplotlib.patches import Patch
except ImportError:
    sys.exit(
        "\nError: matplotlib is not installed.\n"
        "Install it with:  pip install matplotlib\n"
    )


# =============================================================================
# DATA LOADING
# =============================================================================

def load_phase(phase_number):
    """
    Load results/phaseN.csv and return a list of row dicts.
    Each dict has keys: filename, password, time_seconds (float).
    Returns an empty list if the file does not exist.
    """
    path = f"results/phase{phase_number}.csv"
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["time_seconds"] = float(row["time_seconds"])
            rows.append(row)
    return rows


def _latest_per_file(rows, known_files):
    """
    From a list of CSV rows, keep the most recent result for each filename.
    Only includes filenames that appear in known_files.
    Returns a dict: {filename: time_seconds}.
    """
    latest = {}
    for row in rows:
        if row["filename"] in known_files:
            latest[row["filename"]] = row["time_seconds"]
    return latest


# =============================================================================
# SHARED CHART HELPERS
# =============================================================================

COLORS = [
    "#4C72B0",  # blue
    "#DD8452",  # orange
    "#55A868",  # green
    "#C44E52",  # red
    "#8172B2",  # purple
]


def _bar_labels(ax, bars):
    """Print the exact value of each bar just above it."""
    for bar in bars:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height * 1.03,
            f"{height:.3f}s",
            ha="center", va="bottom", fontsize=9,
        )


def _maybe_log_scale(ax, times):
    """Switch to log scale when the range spans more than two orders of magnitude."""
    if max(times) / max(min(times), 1e-9) > 100:
        ax.set_yscale("log")
        ax.yaxis.set_major_formatter(
            ticker.FuncFormatter(lambda v, _: f"{v:.3g}s")
        )
        return True
    return False


def _save(fig, filename):
    os.makedirs("plots", exist_ok=True)
    path = os.path.join("plots", filename)
    fig.savefig(path, bbox_inches="tight", dpi=150)
    print(f"  Saved: {path}")
    plt.close(fig)


# =============================================================================
# CHART 1 — Phase 1: Crack time vs password length
# =============================================================================

PHASE1_FILES = {
    "level1.zip": {"length": 4, "space": "10⁴ = 10,000"},
    "level2.zip": {"length": 5, "space": "10⁵ = 100,000"},
    "level3.zip": {"length": 6, "space": "10⁶ = 1,000,000"},
}


def plot_phase1(rows):
    """
    Bar chart: crack time for each Phase 1 ZIP, ordered by password length.

    Key insight: each extra digit multiplies the search space by 10.
    The bars should grow roughly exponentially — plot them on a log scale
    to make the straight-line pattern visible.
    """
    latest = _latest_per_file(rows, PHASE1_FILES)
    if not latest:
        print("  Phase 1: no data yet — crack the phase1 ZIPs first.")
        return

    files  = sorted(latest, key=lambda f: PHASE1_FILES[f]["length"])
    times  = [latest[f] for f in files]
    labels = [
        f"{PHASE1_FILES[f]['length']}-digit\n({PHASE1_FILES[f]['space']})"
        for f in files
    ]

    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(labels, times, color=COLORS[:len(files)],
                  width=0.5, edgecolor="white", linewidth=0.8)
    _bar_labels(ax, bars)
    log = _maybe_log_scale(ax, times)

    ax.set_title("Phase 1 — Crack Time vs Password Length", fontsize=13, pad=12)
    ax.set_xlabel("Password length (digit-only brute force)", fontsize=11)
    ax.set_ylabel(f"Crack time (seconds){' — log scale' if log else ''}", fontsize=11)
    ax.spines[["top", "right"]].set_visible(False)
    if not log:
        ax.set_ylim(bottom=0)

    fig.tight_layout()
    _save(fig, "phase1_growth.png")


# =============================================================================
# CHART 2 — Phase 2: Brute force vs dictionary
# =============================================================================

PHASE2_FILES = {
    "brute_easy.zip":   {"label": "Brute\n4-lower", "attack": "brute"},
    "brute_medium.zip": {"label": "Brute\n5-lower", "attack": "brute"},
    "dict_easy.zip":    {"label": "Dict\n(sunshine)", "attack": "dictionary"},
    "dict_medium.zip":  {"label": "Dict\n(dragon)",   "attack": "dictionary"},
}

ATTACK_COLORS = {
    "brute":      "#4C72B0",
    "dictionary": "#55A868",
}


def plot_phase2(rows):
    """
    Bar chart comparing brute-force and dictionary crack times.

    Key insight: the dictionary targets (sunshine, dragon) are 8 and 6
    characters long — brute force over lowercase would take hours or days.
    The dictionary attack finds them in seconds. The gap between the blue
    and green bars is the whole point of Phase 2.
    """
    latest = _latest_per_file(rows, PHASE2_FILES)
    if not latest:
        print("  Phase 2: no data yet — crack the phase2 ZIPs first.")
        return

    files  = [f for f in PHASE2_FILES if f in latest]
    times  = [latest[f] for f in files]
    labels = [PHASE2_FILES[f]["label"] for f in files]
    colors = [ATTACK_COLORS[PHASE2_FILES[f]["attack"]] for f in files]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, times, color=colors,
                  width=0.5, edgecolor="white", linewidth=0.8)
    _bar_labels(ax, bars)
    log = _maybe_log_scale(ax, times)

    ax.set_title("Phase 2 — Brute Force vs Dictionary Attack", fontsize=13, pad=12)
    ax.set_xlabel("Target ZIP / attack type", fontsize=11)
    ax.set_ylabel(f"Crack time (seconds){' — log scale' if log else ''}", fontsize=11)
    ax.spines[["top", "right"]].set_visible(False)
    if not log:
        ax.set_ylim(bottom=0)

    legend_elements = [
        Patch(facecolor=ATTACK_COLORS["brute"],      label="Brute force"),
        Patch(facecolor=ATTACK_COLORS["dictionary"], label="Dictionary attack"),
    ]
    ax.legend(handles=legend_elements, frameon=False, fontsize=10)

    fig.tight_layout()
    _save(fig, "phase2_comparison.png")


# =============================================================================
# CHART 3 — Phase 3: Hybrid rule comparison
# =============================================================================

PHASE3_FILES = {
    "hybrid_capitalize.zip": "Capitalise",
    "hybrid_append.zip":     "Append\ndigits",
    "hybrid_leet.zip":       "Leet\nswap",
    "hybrid_suffix.zip":     "Year\nsuffix",
    "hybrid_combo.zip":      "All rules\ncombined",
}


def plot_phase3(rows):
    """
    Bar chart: crack time per hybrid rule type, ordered by rule complexity.

    Key insight: even 'all rules combined' (Sunshine123!) takes milliseconds —
    far faster than brute-forcing an 8-character password. Complexity rules
    produce predictable transformations, not unpredictable passwords.
    """
    latest = _latest_per_file(rows, PHASE3_FILES)
    if not latest:
        print("  Phase 3: no data yet — crack the phase3 ZIPs first.")
        return

    files  = [f for f in PHASE3_FILES if f in latest]
    times  = [latest[f] for f in files]
    labels = [PHASE3_FILES[f] for f in files]
    colors = COLORS[:len(files)]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, times, color=colors,
                  width=0.5, edgecolor="white", linewidth=0.8)
    _bar_labels(ax, bars)
    log = _maybe_log_scale(ax, times)

    ax.set_title("Phase 3 — Hybrid Crack Time by Rule Type", fontsize=13, pad=12)
    ax.set_xlabel("Transformation applied", fontsize=11)
    ax.set_ylabel(f"Crack time (seconds){' — log scale' if log else ''}", fontsize=11)
    ax.spines[["top", "right"]].set_visible(False)
    if not log:
        ax.set_ylim(bottom=0)

    fig.tight_layout()
    _save(fig, "phase3_hybrid.png")


# =============================================================================
# CHART 4 — Summary: all three phases in one figure
# =============================================================================

def _fill_axis(ax, latest, file_meta, title, xlabel, get_label):
    """Draw a single bar chart panel into ax. Uses sequential COLORS. Reused by plot_summary."""
    if not latest:
        ax.text(0.5, 0.5, "No data yet", ha="center", va="center",
                transform=ax.transAxes, fontsize=10, color="grey")
        ax.set_title(title, fontsize=10)
        return

    files  = [f for f in file_meta if f in latest]
    times  = [latest[f] for f in files]
    labels = [get_label(f) for f in files]
    colors = [COLORS[i % len(COLORS)] for i in range(len(files))]

    ax.bar(labels, times, color=colors, width=0.5, edgecolor="white", linewidth=0.6)
    _maybe_log_scale(ax, times)

    ax.set_title(title, fontsize=10)
    ax.set_xlabel(xlabel, fontsize=8)
    ax.set_ylabel("Crack time (s)", fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(axis="x", labelsize=7)


def plot_summary(phase1, phase2, phase3):
    """
    Three-panel figure combining the key result from each phase.
    Suitable for direct inclusion in your report.
    """
    if not any([phase1, phase2, phase3]):
        print("  Summary: no phase data found — complete at least one phase first.")
        return

    latest1 = _latest_per_file(phase1, PHASE1_FILES)
    latest2 = _latest_per_file(phase2, PHASE2_FILES)
    latest3 = _latest_per_file(phase3, PHASE3_FILES)

    fig, axes = plt.subplots(1, 3, figsize=(14, 5))
    fig.suptitle("Password Cracking — Results Summary", fontsize=13, y=1.02)

    _fill_axis(
        axes[0], latest1, PHASE1_FILES,
        title="Phase 1: Digit brute force",
        xlabel="Password length",
        get_label=lambda f: f"{PHASE1_FILES[f]['length']}-digit",
    )
    _fill_axis(
        axes[1], latest2, PHASE2_FILES,
        title="Phase 2: Brute vs dictionary",
        xlabel="Target / attack",
        get_label=lambda f: PHASE2_FILES[f]["label"].replace("\n", " "),
    )
    _fill_axis(
        axes[2], latest3, PHASE3_FILES,
        title="Phase 3: Hybrid rules",
        xlabel="Rule applied",
        get_label=lambda f: PHASE3_FILES[f].replace("\n", " "),
    )

    fig.tight_layout()
    _save(fig, "summary.png")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate charts from your password cracking results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python plot_results.py            # all available charts\n"
            "  python plot_results.py --phase 1  # phase 1 growth chart only\n"
        ),
    )
    parser.add_argument(
        "--phase", type=int, choices=[1, 2, 3],
        help="Generate chart for one phase only (default: all phases + summary)",
    )
    args = parser.parse_args()

    phase1 = load_phase(1)
    phase2 = load_phase(2)
    phase3 = load_phase(3)

    if args.phase == 1 or args.phase is None:
        print("Generating Phase 1 chart...")
        plot_phase1(phase1)

    if args.phase == 2 or args.phase is None:
        print("Generating Phase 2 chart...")
        plot_phase2(phase2)

    if args.phase == 3 or args.phase is None:
        print("Generating Phase 3 chart...")
        plot_phase3(phase3)

    if args.phase is None:
        print("Generating summary chart...")
        plot_summary(phase1, phase2, phase3)

    print("\nDone. Charts saved to plots/")


if __name__ == "__main__":
    main()
