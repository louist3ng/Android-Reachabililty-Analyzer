#!/usr/bin/env python3
"""
Dynamic Analysis Module — Runtime Call Graph Enrichment

Complements the static reachability analyzer by capturing actual method calls
at runtime via Frida instrumentation.  The runtime trace is merged into the
static call graph before BFS traversal, closing gaps caused by reflection,
dynamic dispatch, unrecognised callbacks, and coroutines.

This module is self-contained.  Deleting it has zero effect on reachability.py.

Dependencies (beyond the base tool):
    pip install frida frida-tools

Requires:
    - Android emulator or rooted device accessible via ADB
    - Frida server running on the device (matching the frida Python version)

Usage:
    # Step 1 — Capture a runtime trace (run once, reuse across analyses)
    python dynamic_analysis.py trace --package com.test.reachability \
                                     --output trace.json \
                                     --duration 30

    # Step 2 — Run the full enriched reachability pipeline
    python dynamic_analysis.py enrich --apk target.apk \
                                      --findings mobsf_report.json \
                                      --trace trace.json \
                                      --output report.md

    # Or combine: auto-trace then analyse in one shot
    python dynamic_analysis.py auto --apk target.apk \
                                    --findings mobsf_report.json \
                                    --package com.test.reachability \
                                    --output report.md
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Logging — mirrors reachability.py conventions
# ---------------------------------------------------------------------------

DEBUG = False

def _warn(msg):
    print(f"[WARN] {msg}", file=sys.stderr)

def _info(msg):
    print(f"[INFO] {msg}", file=sys.stderr)

def _debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)

def _error_exit(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Frida JavaScript instrumentation payload
#
# When injected into the target process, this script hooks every method in
# classes whose name starts with the target package prefix.  For each call
# it records (caller, callee) pairs and periodically flushes them to the
# Python host via Frida's send() mechanism.
# ---------------------------------------------------------------------------

_FRIDA_SCRIPT_TEMPLATE = r"""
'use strict';

// Package prefixes to trace (converted from dot to slash notation)
var PREFIXES = %%PREFIXES%%;

// Edge buffer — flushed to Python periodically
var edges = [];
var FLUSH_INTERVAL = 2000;  // ms

function flush() {
    if (edges.length > 0) {
        send({ type: 'edges', payload: edges });
        edges = [];
    }
}

setInterval(flush, FLUSH_INTERVAL);

// Convert a Java method to a Dalvik-style label:
//   Lcom/example/Class;->method(param_sig)return_sig
// We approximate the signature since Frida doesn't give us the full
// Dalvik descriptor easily — we use className + methodName which is
// sufficient for graph enrichment at the class+method tier.
function methodLabel(className, methodName) {
    // className from Frida is dot-separated, convert to Dalvik
    var dalvik = 'L' + className.replace(/\./g, '/') + ';->' + methodName;
    return dalvik;
}

// Determine the caller by inspecting the Java stack trace.
// We walk up the stack to find the first frame in a traced package.
function getCallerLabel() {
    var bt = Java.use('java.lang.Thread').currentThread().getStackTrace();
    // bt[0] = getStackTrace, bt[1] = getCallerLabel proxy, bt[2] = hooked method,
    // bt[3..] = actual callers
    for (var i = 3; i < bt.length && i < 15; i++) {
        var frame = bt[i];
        var cls = frame.getClassName();
        for (var p = 0; p < PREFIXES.length; p++) {
            if (cls.indexOf(PREFIXES[p]) === 0) {
                return methodLabel(cls, frame.getMethodName());
            }
        }
    }
    // No in-package caller found — attribute to framework
    if (bt.length > 3) {
        var f = bt[3];
        return methodLabel(f.getClassName(), f.getMethodName());
    }
    return null;
}

Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            var dominated = false;
            for (var p = 0; p < PREFIXES.length; p++) {
                if (className.indexOf(PREFIXES[p]) === 0) {
                    dominated = true;
                    break;
                }
            }
            if (!dominated) return;

            try {
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();

                for (var m = 0; m < methods.length; m++) {
                    var methodName = methods[m].getName();

                    // Skip common noise methods
                    if (methodName === 'toString' || methodName === 'hashCode' ||
                        methodName === 'equals' || methodName === 'getClass') continue;

                    try {
                        var overloads = clazz[methodName].overloads;
                        for (var o = 0; o < overloads.length; o++) {
                            (function (mName, overload) {
                                overload.implementation = function () {
                                    var callerLabel = getCallerLabel();
                                    var calleeLabel = methodLabel(className, mName);
                                    if (callerLabel && callerLabel !== calleeLabel) {
                                        edges.push({
                                            caller: callerLabel,
                                            callee: calleeLabel
                                        });
                                    }
                                    return overload.apply(this, arguments);
                                };
                            })(methodName, overloads[o]);
                        }
                    } catch (e) {
                        // Some methods can't be hooked (native, abstract) — skip
                    }
                }
            } catch (e) {
                // Class may not be hookable — skip
            }
        },
        onComplete: function () {
            send({ type: 'status', payload: 'hooking_complete' });
        }
    });
});
"""


# ---------------------------------------------------------------------------
# Trace capture
# ---------------------------------------------------------------------------

def _check_frida():
    """Verify frida is importable and return the module."""
    try:
        import frida
        return frida
    except ImportError:
        _error_exit(
            "Frida is not installed.  Install it with:\n"
            "    pip install frida frida-tools\n"
            "Also ensure frida-server is running on the target device.\n"
            "See: https://frida.re/docs/android/"
        )


def _check_adb():
    """Verify ADB is available and at least one device is connected."""
    try:
        result = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=10
        )
        lines = [l for l in result.stdout.strip().split("\n")[1:] if l.strip()]
        devices = [l.split("\t")[0] for l in lines if "device" in l]
        if not devices:
            _error_exit(
                "No Android devices/emulators found.  Start an emulator or connect a device, "
                "then ensure `adb devices` lists it."
            )
        return devices
    except FileNotFoundError:
        _error_exit("ADB not found on PATH.  Install Android SDK platform-tools.")
    except subprocess.TimeoutExpired:
        _error_exit("ADB timed out.  Check your device connection.")


def _run_monkey(package, device=None, events=2000):
    """
    Run Android's monkey tool for automated pseudo-random UI input.
    This exercises the app without manual interaction.
    """
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += [
        "shell", "monkey",
        "-p", package,
        "--throttle", "100",
        "--ignore-crashes",
        "--ignore-timeouts",
        "--ignore-security-exceptions",
        "-v", str(events),
    ]
    _info(f"Running monkey with {events} events on package {package}...")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return proc
    except FileNotFoundError:
        _warn("Could not run monkey (adb not found) — trace will rely on manual interaction")
        return None


def capture_trace(package, duration=30, output_path="trace.json",
                  device=None, monkey_events=2000, extra_prefixes=None):
    """
    Attach Frida to the target app, hook methods, run monkey for automated
    input, and collect a runtime call trace.

    Args:
        package:         Target app package name (e.g. 'com.test.reachability')
        duration:        How many seconds to trace (default 30)
        output_path:     Where to write the JSON trace
        device:          ADB device serial (None = first available)
        monkey_events:   Number of monkey UI events (0 to disable)
        extra_prefixes:  Additional package prefixes to hook
    """
    frida = _check_frida()
    devices = _check_adb()

    if device is None:
        device = devices[0]
        _info(f"Using device: {device}")

    # Build prefix list for Frida script
    prefixes = [package]
    if extra_prefixes:
        prefixes.extend(extra_prefixes)
    # Convert to JavaScript array literal
    prefix_js = json.dumps(prefixes)
    script_source = _FRIDA_SCRIPT_TEMPLATE.replace("%%PREFIXES%%", prefix_js)

    # Collect edges from Frida callbacks
    collected_edges = []
    hooking_done = [False]

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if payload.get("type") == "edges":
                collected_edges.extend(payload["payload"])
                _debug(f"  Received {len(payload['payload'])} edges (total: {len(collected_edges)})")
            elif payload.get("type") == "status" and payload.get("payload") == "hooking_complete":
                hooking_done[0] = True
                _info("Frida hooking complete — tracing active")
        elif message["type"] == "error":
            _warn(f"Frida error: {message.get('description', message)}")

    # Connect to device and spawn/attach to app
    _info(f"Connecting to device {device}...")
    try:
        frida_device = frida.get_device(device, timeout=10)
    except Exception:
        # Try USB device as fallback
        try:
            frida_device = frida.get_usb_device(timeout=10)
        except Exception as e:
            _error_exit(f"Cannot connect to Frida on device: {e}\n"
                        "Ensure frida-server is running on the device.")

    _info(f"Spawning {package}...")
    try:
        pid = frida_device.spawn([package])
        session = frida_device.attach(pid)
    except Exception as e:
        _error_exit(
            f"Failed to spawn/attach to {package}: {e}\n"
            "Ensure the app is installed and frida-server is running."
        )

    script = session.create_script(script_source)
    script.on("message", on_message)
    script.load()
    frida_device.resume(pid)
    _info(f"App launched.  Tracing for {duration} seconds...")

    # Start monkey for automated exercising
    monkey_proc = None
    if monkey_events > 0:
        monkey_proc = _run_monkey(package, device, monkey_events)

    # Wait for the trace duration
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        _info("Interrupted — saving collected trace...")

    # Cleanup
    if monkey_proc:
        monkey_proc.terminate()
        monkey_proc.wait(timeout=5)

    # Final flush
    try:
        script.unload()
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass

    # Deduplicate edges
    seen = set()
    unique_edges = []
    for edge in collected_edges:
        key = (edge["caller"], edge["callee"])
        if key not in seen:
            seen.add(key)
            unique_edges.append(edge)

    trace = {
        "package": package,
        "device": device,
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": duration,
        "monkey_events": monkey_events,
        "total_edge_observations": len(collected_edges),
        "unique_edges": len(unique_edges),
        "edges": unique_edges,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(trace, f, indent=2, ensure_ascii=False)

    _info(f"Trace saved to {output_path}")
    _info(f"  {len(unique_edges)} unique edges from {len(collected_edges)} observations")
    return trace


# ---------------------------------------------------------------------------
# Graph enrichment — merge runtime edges into the static call graph
# ---------------------------------------------------------------------------

def load_trace(trace_path):
    """Load a previously captured trace JSON file."""
    try:
        with open(trace_path, "r", encoding="utf-8") as f:
            trace = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        _error_exit(f"Failed to load trace file: {e}")

    edges = trace.get("edges", [])
    _info(f"Loaded trace: {len(edges)} unique runtime edges "
          f"(captured {trace.get('timestamp', 'unknown')})")
    return trace


def enrich_call_graph(cg, node_by_norm, trace):
    """
    Merge runtime-observed edges into the static call graph.

    For each (caller, callee) pair in the trace:
      1. Try to find matching nodes in the existing graph by normalised label
      2. If both endpoints exist, add the edge (if not already present)
      3. If an endpoint is missing, create a synthetic node and add the edge

    Returns the count of edges added.
    """
    edges = trace.get("edges", [])
    added = 0
    new_nodes = 0

    # Build a reverse index: partial key -> list of (norm_label, node)
    # This allows matching "Lcom/test/Foo;->bar" against full signatures
    # like "Lcom/test/Foo;->bar(Landroid/os/Bundle;)V"
    _debug(f"Enriching call graph with {len(edges)} runtime edges...")

    for edge in edges:
        caller_key = edge["caller"]
        callee_key = edge["callee"]

        caller_node = _find_node(caller_key, node_by_norm)
        callee_node = _find_node(callee_key, node_by_norm)

        if caller_node is None:
            # Create a synthetic node for the caller
            caller_node = caller_key
            cg.add_node(caller_node)
            node_by_norm[caller_key] = caller_node
            new_nodes += 1

        if callee_node is None:
            callee_node = callee_key
            cg.add_node(callee_node)
            node_by_norm[callee_key] = callee_node
            new_nodes += 1

        if not cg.has_edge(caller_node, callee_node):
            cg.add_edge(caller_node, callee_node)
            added += 1
            _debug(f"  +edge: {caller_key} -> {callee_key}")

    _info(f"Runtime enrichment: +{added} edges, +{new_nodes} new nodes "
          f"(graph now: {cg.number_of_nodes()} nodes, {cg.number_of_edges()} edges)")
    return added


def _find_node(partial_label, node_by_norm):
    """
    Find a call-graph node matching a partial Dalvik label from the trace.

    Trace labels look like: Lcom/test/Foo;->bar  (no parameter/return sig)
    Graph labels look like: Lcom/test/Foo;->bar(Landroid/os/Bundle;)V

    Strategy:
      1. Exact match against normalised labels
      2. Prefix match (trace label is a prefix of a graph label)
    """
    # Exact match
    if partial_label in node_by_norm:
        return node_by_norm[partial_label]

    # Prefix match: trace label + "(" should appear in a graph label
    search = partial_label + "("
    for norm_label, node in node_by_norm.items():
        if norm_label.startswith(partial_label) or search in norm_label:
            return node

    # Class+method substring match
    if ";->" in partial_label:
        for norm_label, node in node_by_norm.items():
            # Extract class and method from partial label
            if partial_label in norm_label:
                return node

    return None


# ---------------------------------------------------------------------------
# Enriched reachability pipeline — wraps reachability.py
# ---------------------------------------------------------------------------

def run_enriched_pipeline(apk_path, findings_path, trace_path, output_path,
                          max_depth=15, mobsf_url=None, mobsf_key=None,
                          save_findings=None, debug=False):
    """
    Run the full reachability pipeline with runtime trace enrichment.

    This imports and reuses functions from reachability.py, injecting
    runtime edges into the call graph after static construction but
    before BFS traversal.
    """
    # Import the core module
    try:
        import reachability as ra
    except ImportError:
        _error_exit(
            "Cannot import reachability.py — ensure it is in the same directory "
            "or on PYTHONPATH."
        )

    # Propagate debug flag
    ra.DEBUG = debug
    global DEBUG
    DEBUG = debug

    if not os.path.isfile(apk_path):
        _error_exit(f"APK file not found: {apk_path}")

    # Load the runtime trace
    trace = load_trace(trace_path)

    # --- Stage 1: Obtain findings ---
    findings_data = None
    if mobsf_url:
        if not mobsf_key:
            _error_exit("--mobsf-key is required when using --mobsf-url")
        findings_data = ra.mobsf_auto_scan(mobsf_url, mobsf_key, apk_path, save_findings)

    # --- Stage 2: Build static call graph ---
    apk, dalvik, analysis, cg = ra.build_call_graph(apk_path)

    # Build normalised node index
    node_by_norm, node_obj_to_norm = ra._build_node_index(cg)
    _debug(f"Static graph: {cg.number_of_nodes()} nodes, {cg.number_of_edges()} edges")

    # Inject synthetic callback edges (same as core pipeline)
    ra._inject_callback_edges(cg, node_by_norm)

    # --- Stage 2.5: RUNTIME ENRICHMENT (the new bit) ---
    edges_added = enrich_call_graph(cg, node_by_norm, trace)

    # --- Stage 3: Entry points ---
    entry_points = ra.get_entry_points(apk, cg, node_by_norm)
    if not entry_points:
        _warn("No entry points resolved — all findings will be NOT REACHABLE")

    # --- Stage 4: Parse findings & match sinks ---
    if findings_data is not None:
        findings, source = ra.parse_findings_from_data(findings_data, "mobsf")
    else:
        if not findings_path or not os.path.isfile(findings_path):
            _error_exit(f"Findings file not found: {findings_path}")
        findings, source = ra.parse_findings(findings_path, "mobsf")

    ra.info(f"Parsed {len(findings)} findings from {source}")
    findings = ra.match_sinks(findings, cg, node_by_norm)

    matched = sum(1 for f in findings if f["matched_node"] is not None)
    ra.info(f"Sink matching: {matched}/{len(findings)} findings matched to call graph nodes")

    # --- Stage 5: BFS reachability ---
    ra.info(f"Running reachability analysis (max depth = {max_depth})...")
    findings = ra.run_reachability(cg, entry_points, findings, max_depth)

    # --- Stage 6: FP risk checks ---
    findings = ra.fp_risk_checks(findings, apk)

    # --- Stage 7: Generate report ---
    # Append enrichment metadata to the source name
    source_label = f"{source} + dynamic trace ({trace.get('unique_edges', 0)} runtime edges)"
    ra.generate_report(findings, apk_path, source_label, max_depth, output_path)

    # Summary
    verdicts = {"REACHABLE": 0, "NOT REACHABLE": 0, "UNRESOLVED": 0}
    for f in findings:
        verdicts[f["verdict"]] += 1
    beyond = sum(1 for f in findings
                 if f.get("unbounded_reachable") and f["verdict"] == "NOT REACHABLE")
    ra.info(f"Done (enriched) — REACHABLE: {verdicts['REACHABLE']}, "
            f"NOT REACHABLE: {verdicts['NOT REACHABLE']}, "
            f"UNRESOLVED: {verdicts['UNRESOLVED']}")
    if edges_added:
        ra.info(f"  Runtime enrichment contributed {edges_added} additional edges to the call graph")
    if beyond:
        ra.info(f"  {beyond} finding(s) ARE reachable beyond depth {max_depth} — increase --max-depth to capture them")

    return findings


# ---------------------------------------------------------------------------
# Auto mode — trace + enrich in one shot
# ---------------------------------------------------------------------------

def run_auto(apk_path, findings_path, package, output_path,
             duration=30, max_depth=15, monkey_events=2000,
             device=None, mobsf_url=None, mobsf_key=None,
             save_findings=None, debug=False):
    """
    Fully automated: capture a runtime trace, then run the enriched pipeline.
    """
    trace_path = output_path.rsplit(".", 1)[0] + "_trace.json"

    _info("=== Phase 1: Runtime Trace Capture ===")
    capture_trace(
        package=package,
        duration=duration,
        output_path=trace_path,
        device=device,
        monkey_events=monkey_events,
    )

    _info("=== Phase 2: Enriched Reachability Analysis ===")
    return run_enriched_pipeline(
        apk_path=apk_path,
        findings_path=findings_path,
        trace_path=trace_path,
        output_path=output_path,
        max_depth=max_depth,
        mobsf_url=mobsf_url,
        mobsf_key=mobsf_key,
        save_findings=save_findings,
        debug=debug,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    global DEBUG

    parser = argparse.ArgumentParser(
        description="Dynamic Analysis Module — runtime call graph enrichment "
                    "for the Android Reachability Analyzer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
commands:
  trace    Capture a runtime call trace via Frida instrumentation
  enrich   Run the reachability pipeline with runtime trace enrichment
  auto     Capture trace + run enriched analysis in one shot

examples:
  python dynamic_analysis.py trace --package com.test.app -o trace.json
  python dynamic_analysis.py enrich --apk app.apk --findings report.json --trace trace.json
  python dynamic_analysis.py auto --apk app.apk --findings report.json --package com.test.app
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- trace ---
    p_trace = sub.add_parser("trace", help="Capture a runtime call trace via Frida")
    p_trace.add_argument("--package", required=True,
                         help="Target app package name (e.g. com.test.reachability)")
    p_trace.add_argument("-o", "--output", default="trace.json",
                         help="Output trace file path (default: trace.json)")
    p_trace.add_argument("--duration", type=int, default=30,
                         help="Trace duration in seconds (default: 30)")
    p_trace.add_argument("--device", default=None,
                         help="ADB device serial (default: first available)")
    p_trace.add_argument("--monkey-events", type=int, default=2000,
                         help="Number of monkey UI events (0 to disable, default: 2000)")
    p_trace.add_argument("--extra-prefix", action="append", default=[],
                         help="Additional package prefixes to trace (repeatable)")
    p_trace.add_argument("--debug", action="store_true")

    # --- enrich ---
    p_enrich = sub.add_parser("enrich",
                              help="Run reachability analysis with runtime trace enrichment")
    p_enrich.add_argument("--apk", required=True, help="Path to the APK file")
    p_enrich.add_argument("--findings", default=None,
                          help="Path to MobSF findings JSON")
    p_enrich.add_argument("--trace", required=True,
                          help="Path to runtime trace JSON (from 'trace' command)")
    p_enrich.add_argument("-o", "--output", default="report.md",
                          help="Output report path (default: report.md)")
    p_enrich.add_argument("--max-depth", type=int, default=15,
                          help="Max BFS depth (default: 15)")
    p_enrich.add_argument("--mobsf-url", default=None, help="MobSF server URL")
    p_enrich.add_argument("--mobsf-key", default=None, help="MobSF API key")
    p_enrich.add_argument("--save-findings", default=None,
                          help="Save MobSF report JSON to disk")
    p_enrich.add_argument("--debug", action="store_true")

    # --- auto ---
    p_auto = sub.add_parser("auto",
                            help="Capture trace + enriched analysis in one shot")
    p_auto.add_argument("--apk", required=True, help="Path to the APK file")
    p_auto.add_argument("--findings", default=None,
                        help="Path to MobSF findings JSON")
    p_auto.add_argument("--package", required=True,
                        help="Target app package name")
    p_auto.add_argument("-o", "--output", default="report.md",
                        help="Output report path (default: report.md)")
    p_auto.add_argument("--duration", type=int, default=30,
                        help="Trace duration in seconds (default: 30)")
    p_auto.add_argument("--max-depth", type=int, default=15,
                        help="Max BFS depth (default: 15)")
    p_auto.add_argument("--monkey-events", type=int, default=2000,
                        help="Number of monkey events (0 to disable, default: 2000)")
    p_auto.add_argument("--device", default=None, help="ADB device serial")
    p_auto.add_argument("--mobsf-url", default=None, help="MobSF server URL")
    p_auto.add_argument("--mobsf-key", default=None, help="MobSF API key")
    p_auto.add_argument("--save-findings", default=None,
                        help="Save MobSF report JSON to disk")
    p_auto.add_argument("--debug", action="store_true")

    args = parser.parse_args()
    DEBUG = getattr(args, "debug", False)

    if args.command == "trace":
        capture_trace(
            package=args.package,
            duration=args.duration,
            output_path=args.output,
            device=args.device,
            monkey_events=args.monkey_events,
            extra_prefixes=args.extra_prefix or None,
        )

    elif args.command == "enrich":
        run_enriched_pipeline(
            apk_path=args.apk,
            findings_path=args.findings,
            trace_path=args.trace,
            output_path=args.output,
            max_depth=args.max_depth,
            mobsf_url=args.mobsf_url,
            mobsf_key=args.mobsf_key,
            save_findings=args.save_findings,
            debug=DEBUG,
        )

    elif args.command == "auto":
        run_auto(
            apk_path=args.apk,
            findings_path=args.findings,
            package=args.package,
            output_path=args.output,
            duration=args.duration,
            max_depth=args.max_depth,
            monkey_events=args.monkey_events,
            device=args.device,
            mobsf_url=args.mobsf_url,
            mobsf_key=args.mobsf_key,
            save_findings=args.save_findings,
            debug=DEBUG,
        )


if __name__ == "__main__":
    main()
