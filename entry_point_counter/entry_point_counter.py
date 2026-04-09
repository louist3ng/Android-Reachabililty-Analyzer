#!/usr/bin/env python3
"""
Entry Point Counter — uploads an APK to MobSF, fetches the JSON report,
and counts the number of activities, services, and receivers declared
in the manifest. Results are written to a CSV file.
"""

import argparse
import csv
import json
import os
import sys
import time
from urllib import request as urllib_request
from urllib import parse as urllib_parse
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# MobSF connection settings — fill these in before running
# ---------------------------------------------------------------------------
MOBSF_API_KEY = ""       # e.g. "091488ca5d4b61f5ca5340478c060d668d78db5d1d80e0bd247a5b9c0a06b554"
MOBSF_BASE_URL = ""      # e.g. "http://localhost:8000"

# ---------------------------------------------------------------------------
# MobSF API helpers (stdlib-only, mirrors reachability.py conventions)
# ---------------------------------------------------------------------------

SCAN_TIMEOUT = 300  # max seconds to wait for scan completion

def _mobsf_api(base_url, api_key, endpoint, data=None, files=None, timeout=60):
    """POST to a MobSF REST API endpoint. Returns parsed JSON."""
    full_url = base_url.rstrip("/") + endpoint
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
                f"Content-Disposition: form-data; name=\"{field_name}\"; "
                f"filename=\"{filename}\"\r\n"
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
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        print(f"[ERROR] MobSF API error {e.code} on {endpoint}: {error_body}",
              file=sys.stderr)
        sys.exit(1)
    except URLError as e:
        print(f"[ERROR] Cannot connect to MobSF at {full_url}: {e.reason}",
              file=sys.stderr)
        sys.exit(1)


def upload_apk(base_url, api_key, apk_path):
    """Upload an APK to MobSF. Returns the file hash."""
    filename = os.path.basename(apk_path)
    print(f"[INFO] Uploading '{filename}' to MobSF...")
    with open(apk_path, "rb") as f:
        apk_bytes = f.read()
    result = _mobsf_api(base_url, api_key, "/api/v1/upload",
                        files={"file": (filename, apk_bytes)})
    file_hash = result.get("hash", "")
    if not file_hash:
        print(f"[ERROR] Upload succeeded but no hash returned: {result}",
              file=sys.stderr)
        sys.exit(1)
    print(f"[INFO] Upload complete. Hash: {file_hash}")
    return file_hash


def trigger_scan(base_url, api_key, file_hash, apk_path):
    """Trigger a scan. Returns the report dict if MobSF responds synchronously."""
    filename = os.path.basename(apk_path)
    print("[INFO] Triggering MobSF static analysis scan...")
    result = _mobsf_api(base_url, api_key, "/api/v1/scan",
                        data={"hash": file_hash,
                              "scan_type": "apk",
                              "file_name": filename},
                        timeout=SCAN_TIMEOUT)
    if "activities" in result:
        print("[INFO] Scan completed (synchronous response).")
        return result
    print("[INFO] Scan initiated. Waiting for report...")
    return None


def fetch_report(base_url, api_key, file_hash):
    """Poll for the JSON report until it's ready."""
    poll_interval = 5
    elapsed = 0
    while elapsed < SCAN_TIMEOUT:
        time.sleep(poll_interval)
        elapsed += poll_interval
        print(f"[INFO]   Polling... ({elapsed}s elapsed)")
        try:
            result = _mobsf_api(base_url, api_key, "/api/v1/report_json",
                                data={"hash": file_hash})
            if result and "activities" in result:
                print("[INFO] Report is ready.")
                return result
        except SystemExit:
            if elapsed < SCAN_TIMEOUT:
                continue
            raise
    print(f"[ERROR] Scan did not complete within {SCAN_TIMEOUT}s.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Manifest counting
# ---------------------------------------------------------------------------

def count_entry_points(report):
    """Extract activity, service, and receiver counts from the MobSF report."""
    activities = report.get("activities", [])
    services = report.get("services", [])
    receivers = report.get("receivers", [])

    if activities is None:
        activities = []
    if services is None:
        services = []
    if receivers is None:
        receivers = []

    return len(activities), len(services), len(receivers)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Count Android entry points (activities, services, receivers) "
                    "via MobSF API and write results to CSV.")
    parser.add_argument("apk", help="Path to the APK file")
    parser.add_argument("output", help="Output CSV file path")
    args = parser.parse_args()

    # Validate constants
    api_key = MOBSF_API_KEY
    base_url = MOBSF_BASE_URL
    if not api_key:
        print("[ERROR] MOBSF_API_KEY is not set. Edit the constant at the top of this script.",
              file=sys.stderr)
        sys.exit(1)
    if not base_url:
        print("[ERROR] MOBSF_BASE_URL is not set. Edit the constant at the top of this script.",
              file=sys.stderr)
        sys.exit(1)

    # Validate APK path
    if not os.path.isfile(args.apk):
        print(f"[ERROR] APK not found: {args.apk}", file=sys.stderr)
        sys.exit(1)

    # Upload -> Scan -> Fetch report
    file_hash = upload_apk(base_url, api_key, args.apk)
    report = trigger_scan(base_url, api_key, file_hash, args.apk)
    if report is None:
        report = fetch_report(base_url, api_key, file_hash)

    # Count manifest entries
    activity_count, service_count, receiver_count = count_entry_points(report)
    apk_name = os.path.basename(args.apk)

    # Write CSV
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["apk_name", "activity_count", "service_count", "receiver_count"])
        writer.writerow([apk_name, activity_count, service_count, receiver_count])

    print(f"\n[INFO] Results written to {args.output}")

    # Print summary
    print(f"\n--- Entry Point Summary for {apk_name} ---")
    print(f"  Activities: {activity_count}")
    print(f"  Services:   {service_count}")
    print(f"  Receivers:  {receiver_count}")
    print(f"  Total:      {activity_count + service_count + receiver_count}")


if __name__ == "__main__":
    main()
