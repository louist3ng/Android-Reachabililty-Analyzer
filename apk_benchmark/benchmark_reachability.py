#!/usr/bin/env python3
"""Benchmark reachability analysis across multiple BFS depths."""

import argparse
import os
import re
import subprocess
import sys
import time

DEPTHS = [5, 10, 15, 20, 25, 30, 35, 40]

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REACHABILITY_PY = os.path.join(REPO_ROOT, "reachability.py")


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

    start = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.monotonic() - start

    if result.returncode != 0:
        print(f"  [ERROR] depth {depth} failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    return elapsed


def main():
    parser = argparse.ArgumentParser(
        description=f"Benchmark reachability.py across BFS depths {DEPTHS[0]}-{DEPTHS[-1]}.")
    parser.add_argument("--apk", required=True, help="Path to the APK file")
    parser.add_argument("--mobsf-url", required=True,
                        help="MobSF server URL (e.g. http://localhost:8000)")
    parser.add_argument("--mobsf-key", required=True, help="MobSF REST API key")
    args = parser.parse_args()

    apk_path = os.path.abspath(args.apk)
    apk_stem = os.path.splitext(os.path.basename(apk_path))[0]
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), apk_stem)
    os.makedirs(out_dir, exist_ok=True)

    findings_path = os.path.join(out_dir, "mobsf_findings.json")
    python = sys.executable
    rows = []

    # Run MobSF scan once (untimed) to fetch and save findings
    print("Fetching MobSF findings ...", end=" ", flush=True)
    scan_report = os.path.join(out_dir, "_scan_tmp.md")
    run_depth(
        python, apk_path, DEPTHS[0], scan_report,
        findings_path=None,
        mobsf_url=args.mobsf_url, mobsf_key=args.mobsf_key,
        save_findings=findings_path,
    )
    if os.path.isfile(scan_report):
        os.remove(scan_report)
    print("done")

    # Run each depth using saved findings (timed)
    for depth in DEPTHS:
        report_path = os.path.join(out_dir, f"depth_{depth}.md")
        print(f"Running depth {depth} ...", end=" ", flush=True)

        elapsed = run_depth(
            python, apk_path, depth, report_path,
            findings_path=findings_path,
        )

        counts = parse_verdicts(report_path)
        rows.append((depth, counts, elapsed))
        print(f"{elapsed:.1f}s  "
              f"R={counts['REACHABLE']} NR={counts['NOT REACHABLE']} "
              f"U={counts['UNRESOLVED']}")

    # Write summary
    summary_path = os.path.join(out_dir, "summary.md")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(f"# Benchmark Summary — {apk_stem}\n\n")
        f.write("| Depth | REACHABLE | NOT REACHABLE | UNRESOLVED | Time (s) |\n")
        f.write("|------:|----------:|--------------:|-----------:|---------:|\n")
        for depth, counts, elapsed in rows:
            f.write(f"| {depth} | {counts['REACHABLE']} | "
                    f"{counts['NOT REACHABLE']} | {counts['UNRESOLVED']} | "
                    f"{elapsed:.1f} |\n")
        f.write(
            "\n> **Note:** All times reflect static analysis only. "
            "MobSF scan overhead is excluded — findings are fetched "
            "once before benchmarking begins.\n"
        )

    print(f"\nSummary written to {summary_path}")


if __name__ == "__main__":
    main()
