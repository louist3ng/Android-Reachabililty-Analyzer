#!/usr/bin/env python3
"""Count Android manifest entry points for each benchmark APK.

Uses cached MobSF JSON reports (from apk_benchmark/<name>/mobsf_findings.json).
If a cached report is missing, uploads the APK to MobSF and scans it first.

Usage:
    python count_entry_points.py
    python count_entry_points.py --mobsf-url http://localhost:8000 --mobsf-key API_KEY
    python count_entry_points.py --output entry_points_summary.md
"""

import argparse
import json
import os
import sys
import time
from urllib import request as urllib_request, parse as urllib_parse
from urllib.error import HTTPError, URLError

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
BENCHMARK_DIR = os.path.join(REPO_ROOT, "apk_benchmark")
APK_DIR = os.path.join(os.path.dirname(REPO_ROOT), "APK for testing")

# Same 10 APKs as benchmark_reachability.py
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

MOBSF_POLL_INTERVAL = 5
MOBSF_POLL_TIMEOUT = 300


# ---------------------------------------------------------------------------
# MobSF helpers (same as reachability.py, stdlib-only)
# ---------------------------------------------------------------------------

def _mobsf_api(url, api_key, endpoint, data=None, files=None, timeout=60):
    full_url = url.rstrip("/") + endpoint
    headers = {"Authorization": api_key}

    if files:
        boundary = "----EntryPointCounterBoundary"
        body_parts = []
        if data:
            for key, val in data.items():
                body_parts.append(
                    f"--{boundary}\r\n"
                    f"Content-Disposition: form-data; name=\"{key}\"\r\n\r\n"
                    f"{val}\r\n"
                )
        for field_name, (filename, file_bytes) in files.items():
            body_parts.append(
                f"--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n"
            )
            body_parts.append(file_bytes)
            body_parts.append(b"\r\n")
        body_parts.append(f"--{boundary}--\r\n")
        body = b""
        for part in body_parts:
            body += part.encode("utf-8") if isinstance(part, str) else part
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif data:
        body = urllib_parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        body = b""

    req = urllib_request.Request(full_url, data=body, headers=headers, method="POST")
    with urllib_request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def mobsf_scan_apk(url, api_key, apk_path):
    """Upload + scan an APK via MobSF. Returns the full report JSON."""
    filename = os.path.basename(apk_path)
    print(f"  Uploading {filename} to MobSF...", flush=True)
    with open(apk_path, "rb") as f:
        apk_bytes = f.read()
    result = _mobsf_api(url, api_key, "/api/v1/upload",
                        files={"file": (filename, apk_bytes)})
    file_hash = result.get("hash", "")
    if not file_hash:
        print(f"  ERROR: no hash returned from upload", file=sys.stderr)
        return None

    print(f"  Scanning (hash={file_hash[:12]}...)...", flush=True)
    scan_result = _mobsf_api(url, api_key, "/api/v1/scan",
                             data={"hash": file_hash,
                                   "scan_type": "apk",
                                   "file_name": filename},
                             timeout=MOBSF_POLL_TIMEOUT)
    if scan_result and "code_analysis" in scan_result:
        return scan_result

    # Poll fallback
    elapsed = 0
    while elapsed < MOBSF_POLL_TIMEOUT:
        time.sleep(MOBSF_POLL_INTERVAL)
        elapsed += MOBSF_POLL_INTERVAL
        try:
            result = _mobsf_api(url, api_key, "/api/v1/report_json",
                                data={"hash": file_hash})
            if result and "code_analysis" in result:
                return result
        except Exception:
            if elapsed < MOBSF_POLL_TIMEOUT:
                continue
            raise
    return None


# ---------------------------------------------------------------------------
# Entry point counting
# ---------------------------------------------------------------------------

def count_entry_points(report):
    """Extract entry point counts from a MobSF report JSON."""
    activities = report.get("activities", [])
    services = report.get("services", [])
    receivers = report.get("receivers", [])
    providers = report.get("providers", [])

    exported = report.get("exported_count", {})

    return {
        "activities": len(activities),
        "services": len(services),
        "receivers": len(receivers),
        "providers": len(providers),
        "total": len(activities) + len(services) + len(receivers) + len(providers),
        "exported_activities": exported.get("exported_activities", 0),
        "exported_services": exported.get("exported_services", 0),
        "exported_receivers": exported.get("exported_receivers", 0),
        "exported_providers": exported.get("exported_providers", 0),
        "package": report.get("package_name", "unknown"),
    }


def load_or_scan(display_name, apk_filename, mobsf_url, mobsf_key):
    """Load cached MobSF JSON or scan via MobSF if needed."""
    cached = os.path.join(BENCHMARK_DIR, display_name, "mobsf_findings.json")
    if os.path.isfile(cached):
        print(f"  Using cached report: {cached}")
        with open(cached, encoding="utf-8") as f:
            return json.load(f)

    if not mobsf_url or not mobsf_key:
        print(f"  SKIP: no cached report and no MobSF credentials provided",
              file=sys.stderr)
        return None

    apk_path = os.path.join(APK_DIR, apk_filename)
    if not os.path.isfile(apk_path):
        print(f"  SKIP: APK not found at {apk_path}", file=sys.stderr)
        return None

    report = mobsf_scan_apk(mobsf_url, mobsf_key, apk_path)
    if report:
        # Cache for future runs
        out_dir = os.path.join(BENCHMARK_DIR, display_name)
        os.makedirs(out_dir, exist_ok=True)
        with open(cached, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    return report


def generate_summary(results):
    """Generate a Markdown summary table."""
    lines = []
    lines.append("# Entry Point Summary (Manifest Components)")
    lines.append("")
    lines.append("| APK | Package | Activities | Services | Receivers | Providers | **Total** | Exp. Act | Exp. Svc | Exp. Rcv | Exp. Prv |")
    lines.append("|-----|---------|-----------|----------|-----------|-----------|-----------|----------|----------|----------|----------|")

    grand = {"activities": 0, "services": 0, "receivers": 0, "providers": 0,
             "total": 0, "exported_activities": 0, "exported_services": 0,
             "exported_receivers": 0, "exported_providers": 0}

    for name, counts in results:
        lines.append(
            f"| {name} | {counts['package']} | {counts['activities']} | "
            f"{counts['services']} | {counts['receivers']} | "
            f"{counts['providers']} | **{counts['total']}** | "
            f"{counts['exported_activities']} | {counts['exported_services']} | "
            f"{counts['exported_receivers']} | {counts['exported_providers']} |"
        )
        for k in grand:
            grand[k] += counts[k]

    lines.append(
        f"| **TOTAL** | | {grand['activities']} | {grand['services']} | "
        f"{grand['receivers']} | {grand['providers']} | **{grand['total']}** | "
        f"{grand['exported_activities']} | {grand['exported_services']} | "
        f"{grand['exported_receivers']} | {grand['exported_providers']} |"
    )
    lines.append("")
    lines.append(f"*{len(results)} APKs analyzed*")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Count manifest entry points for benchmark APKs")
    parser.add_argument("--mobsf-url", help="MobSF server URL (for uncached APKs)")
    parser.add_argument("--mobsf-key", help="MobSF API key (for uncached APKs)")
    parser.add_argument("--output", default=None,
                        help="Output Markdown file (default: stdout + entry_points_summary.md)")
    args = parser.parse_args()

    output_path = args.output or os.path.join(SCRIPT_DIR, "entry_points_summary.md")

    results = []
    for display_name, apk_filename in REGISTERED_APKS:
        print(f"\n[{display_name}]")
        report = load_or_scan(display_name, apk_filename,
                              args.mobsf_url, args.mobsf_key)
        if report is None:
            print(f"  SKIPPED")
            continue
        counts = count_entry_points(report)
        results.append((display_name, counts))
        print(f"  Activities={counts['activities']}  Services={counts['services']}  "
              f"Receivers={counts['receivers']}  Providers={counts['providers']}  "
              f"Total={counts['total']}")

    if not results:
        print("\nNo APKs processed.", file=sys.stderr)
        sys.exit(1)

    summary = generate_summary(results)
    print(f"\n{'='*70}")
    print(summary)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(summary)
    print(f"\nSummary written to {output_path}")


if __name__ == "__main__":
    main()
