#!/usr/bin/env python3
"""Benchmark reachability analysis across multiple BFS depths.

Runs all registered APKs automatically.  Each depth is executed twice
(with PYTHONHASHSEED=0 for deterministic call-graph construction) and
the average wall-clock time is reported alongside verdict counts.
"""

import argparse
import os
import subprocess
import sys
import time

DEPTHS = [5, 10, 15, 20, 25, 30, 35, 40]
NUM_RUNS = 2  # runs per depth for averaging

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REACHABILITY_PY = os.path.join(REPO_ROOT, "reachability.py")

# Default APK directory (sibling of the repo root)
_APK_DIR = os.path.join(os.path.dirname(REPO_ROOT), "APK for testing")

# Pre-registered APKs — add or remove entries as needed.
# Each tuple is (display_name, filename_inside_APK_DIR).
REGISTERED_APKS = [
    ("reachabilityv4",  "reachabilityv4.apk"),
    ("AndroGoat",       "AndroGoat.apk"),
    ("Uptodown",        "uptodown-com.github.android.apk"),
    ("Calendar",        "calendar-fdroid-release.apk"),
    ("NewPipe",         "NewPipe_v0.28.4.apk"),
    ("Seal",            "Seal-1.13.1-armeabi-v7a-release.apk"),
    ("Briar",           "briar.apk"),
    ("VLC",             "org.videolan.vlc_13070008.apk"),
    ("Wire",            "com.wire.android-v4.23.0-88426-prod-compatrelease.apk"),
    ("Iceraven",        "iceraven-2.42.1-browser-arm64-v8a-forkRelease.apk"),
]


def parse_verdicts(report_path):
    """Count verdict headings in a Markdown report."""
    counts = {"REACHABLE": 0, "NOT REACHABLE": 0, "UNRESOLVED": 0}
    with open(report_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("## [REACHABLE]"):
                counts["REACHABLE"] += 1
            elif line.startswith("## [NOT REACHABLE]"):
                counts["NOT REACHABLE"] += 1
            elif line.startswith("## [UNRESOLVED]"):
                counts["UNRESOLVED"] += 1
    return counts


def run_depth(python, apk, depth, output_path, findings_path,
              mobsf_url=None, mobsf_key=None, save_findings=None):
    """Run reachability.py for a single depth and return wall-clock seconds."""
    cmd = [
        python, REACHABILITY_PY,
        "--apk", apk,
        "--max-depth", str(depth),
        "--output", output_path,
    ]
    if findings_path and os.path.isfile(findings_path):
        cmd += ["--findings", findings_path]
    else:
        cmd += ["--mobsf-url", mobsf_url, "--mobsf-key", mobsf_key]
        if save_findings:
            cmd += ["--save-findings", save_findings]

    # Force deterministic hash seed so Androguard builds identical
    # call graphs across subprocess invocations.
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"

    start = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    elapsed = time.monotonic() - start

    if result.returncode != 0:
        print(f"  [ERROR] depth {depth} failed:\n{result.stderr}", file=sys.stderr)
        return None  # non-fatal — skip this depth

    return elapsed


def benchmark_single_apk(python, apk_path, display_name, out_dir,
                          mobsf_url, mobsf_key):
    """Benchmark one APK: fetch findings once, then run each depth NUM_RUNS times."""
    os.makedirs(out_dir, exist_ok=True)
    findings_path = os.path.join(out_dir, "mobsf_findings.json")

    # Fetch MobSF findings once (untimed)
    print(f"\n{'='*60}")
    print(f"  {display_name}")
    print(f"{'='*60}")
    print("  Fetching MobSF findings ...", end=" ", flush=True)
    scan_report = os.path.join(out_dir, "_scan_tmp.md")
    run_depth(
        python, apk_path, DEPTHS[0], scan_report,
        findings_path=None,
        mobsf_url=mobsf_url, mobsf_key=mobsf_key,
        save_findings=findings_path,
    )
    if os.path.isfile(scan_report):
        os.remove(scan_report)
    print("done")

    # Run each depth NUM_RUNS times
    rows = []  # [(depth, counts, [elapsed_1, elapsed_2, ...], avg_elapsed)]
    for depth in DEPTHS:
        times = []
        last_counts = None
        for run_idx in range(1, NUM_RUNS + 1):
            suffix = f"depth_{depth}_run{run_idx}"
            report_path = os.path.join(out_dir, f"{suffix}.md")
            elapsed = run_depth(
                python, apk_path, depth, report_path,
                findings_path=findings_path,
            )
            if elapsed is None:
                continue
            times.append(elapsed)
            last_counts = parse_verdicts(report_path)

        if not times or last_counts is None:
            print(f"  Depth {depth}: SKIPPED (all runs failed)")
            continue

        avg_elapsed = sum(times) / len(times)
        rows.append((depth, last_counts, times, avg_elapsed))

        run_strs = "  ".join(f"R{i+1}={t:.1f}s" for i, t in enumerate(times))
        print(f"  Depth {depth:>2}:  R={last_counts['REACHABLE']:>3}  "
              f"NR={last_counts['NOT REACHABLE']:>3}  "
              f"U={last_counts['UNRESOLVED']:>2}  |  "
              f"{run_strs}  avg={avg_elapsed:.1f}s")

    # Keep the last single-run report for each depth (for reference)
    # Write the final depth report (from last run) as the canonical one
    for depth in DEPTHS:
        last_run = os.path.join(out_dir, f"depth_{depth}_run{NUM_RUNS}.md")
        canonical = os.path.join(out_dir, f"depth_{depth}.md")
        if os.path.isfile(last_run) and last_run != canonical:
            import shutil
            shutil.copy2(last_run, canonical)

    return rows


def write_apk_summary(out_dir, display_name, rows):
    """Write per-APK summary Markdown."""
    summary_path = os.path.join(out_dir, "summary.md")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(f"# Benchmark Summary — {display_name}\n\n")
        f.write("| Depth | REACHABLE | NOT REACHABLE | UNRESOLVED |")
        for i in range(NUM_RUNS):
            f.write(f" Run {i+1} (s) |")
        f.write(" Avg (s) |\n")

        f.write("|------:|----------:|--------------:|-----------:|")
        for _ in range(NUM_RUNS):
            f.write("---------:|")
        f.write("--------:|\n")

        for depth, counts, times, avg in rows:
            f.write(f"| {depth} | {counts['REACHABLE']} | "
                    f"{counts['NOT REACHABLE']} | {counts['UNRESOLVED']} |")
            for t in times:
                f.write(f" {t:.1f} |")
            f.write(f" {avg:.1f} |\n")

        f.write(
            f"\n> **Note:** Each depth was run {NUM_RUNS} times. "
            "All times reflect static analysis only — MobSF scan overhead "
            "is excluded. PYTHONHASHSEED=0 is used for deterministic results.\n"
        )
    return summary_path


def write_master_summary(bench_dir, all_results):
    """Write a single cross-APK comparison table."""
    summary_path = os.path.join(bench_dir, "master_summary.md")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# Master Benchmark Summary — All APKs\n\n")

        # Table 1: Verdict counts at each depth
        f.write("## Verdict Counts (REACHABLE) by Depth\n\n")
        f.write("| APK |")
        for d in DEPTHS:
            f.write(f" D{d} |")
        f.write(" Total | Peak R | Sat. Depth | UNRES |\n")

        f.write("|-----|")
        for _ in DEPTHS:
            f.write("----:|")
        f.write("------:|-------:|-----------:|------:|\n")

        for name, rows in all_results:
            if not rows:
                continue
            f.write(f"| {name} |")
            total = 0
            peak_r = 0
            sat_depth = DEPTHS[0]
            unres = 0
            r_by_depth = {}
            for depth, counts, times, avg in rows:
                r = counts["REACHABLE"]
                r_by_depth[depth] = r
                f.write(f" {r} |")
                total = r + counts["NOT REACHABLE"] + counts["UNRESOLVED"]
                if r > peak_r:
                    peak_r = r
                    sat_depth = depth
                unres = counts["UNRESOLVED"]
            f.write(f" {total} | {peak_r} | {sat_depth} | {unres} |\n")

        # Table 2: Average timing at each depth
        f.write("\n## Average Analysis Time (seconds) by Depth\n\n")
        f.write("| APK |")
        for d in DEPTHS:
            f.write(f" D{d} |")
        f.write("\n")

        f.write("|-----|")
        for _ in DEPTHS:
            f.write("------:|")
        f.write("\n")

        for name, rows in all_results:
            if not rows:
                continue
            f.write(f"| {name} |")
            for depth, counts, times, avg in rows:
                f.write(f" {avg:.1f} |")
            f.write("\n")

        f.write(
            f"\n> Each depth was run {NUM_RUNS} times and averaged. "
            "MobSF scan overhead is excluded. "
            "PYTHONHASHSEED=0 is used for deterministic call-graph construction.\n"
        )

    return summary_path


def main():
    parser = argparse.ArgumentParser(
        description=f"Benchmark reachability.py across BFS depths "
                    f"{DEPTHS[0]}-{DEPTHS[-1]} for all registered APKs.")
    parser.add_argument("--apk", default=None,
                        help="Path to a single APK (overrides built-in list)")
    parser.add_argument("--mobsf-url", required=True,
                        help="MobSF server URL (e.g. http://localhost:8000)")
    parser.add_argument("--mobsf-key", required=True, help="MobSF REST API key")
    parser.add_argument("--apk-dir", default=_APK_DIR,
                        help="Directory containing the APK files "
                             f"(default: {_APK_DIR})")
    args = parser.parse_args()

    python = sys.executable
    bench_dir = os.path.dirname(os.path.abspath(__file__))

    # Build APK list
    if args.apk:
        # Single APK mode (backwards compatible)
        apk_path = os.path.abspath(args.apk)
        stem = os.path.splitext(os.path.basename(apk_path))[0]
        apk_list = [(stem, apk_path)]
    else:
        # All registered APKs
        apk_list = []
        for name, filename in REGISTERED_APKS:
            path = os.path.join(args.apk_dir, filename)
            if not os.path.isfile(path):
                print(f"[WARN] APK not found, skipping: {path}", file=sys.stderr)
                continue
            apk_list.append((name, path))

    if not apk_list:
        print("No APKs found to benchmark.", file=sys.stderr)
        sys.exit(1)

    print(f"Benchmarking {len(apk_list)} APK(s) x {len(DEPTHS)} depths x "
          f"{NUM_RUNS} runs = {len(apk_list) * len(DEPTHS) * NUM_RUNS} total runs")

    all_results = []
    total_start = time.monotonic()

    for name, apk_path in apk_list:
        out_dir = os.path.join(bench_dir, name)
        rows = benchmark_single_apk(
            python, apk_path, name, out_dir,
            args.mobsf_url, args.mobsf_key,
        )
        if rows:
            summary = write_apk_summary(out_dir, name, rows)
            print(f"  Summary: {summary}")
        all_results.append((name, rows))

    total_elapsed = time.monotonic() - total_start

    # Write master summary
    if len(all_results) > 1:
        master = write_master_summary(bench_dir, all_results)
        print(f"\nMaster summary: {master}")

    minutes = total_elapsed / 60
    print(f"\nTotal benchmark time: {minutes:.1f} minutes")


if __name__ == "__main__":
    main()
