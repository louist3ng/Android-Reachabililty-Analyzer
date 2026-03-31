#!/usr/bin/env python3
"""
Dynamic Analysis Module — Runtime Trace Capture & Cross-Validation Helpers

Provides two capabilities:
  1. Frida-based runtime trace capture (standalone CLI: `python dynamic_analysis.py trace`)
  2. Helper functions imported by reachability.py when --dynamic is used

This module is self-contained.  Deleting it has zero effect on reachability.py
(the --dynamic flag will simply be unavailable).

Dependencies (beyond the base tool):
    pip install frida frida-tools

Requires:
    - Android emulator or rooted device accessible via ADB
    - Frida server running on the device (matching the frida Python version)

Usage:
    # Capture a runtime trace (run once, reuse across analyses)
    python dynamic_analysis.py trace --apk target.apk --output trace.json --duration 30

    # Then use the trace with the main tool:
    python reachability.py --apk target.apk --findings report.json --dynamic trace.json --output report.md
"""

import argparse
import json
import lzma
import os
import subprocess
import sys
import time
import urllib.request
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

function hookAll() {
    send({ type: 'diag', payload: 'hookAll called, Java.available=' + Java.available });
    Java.perform(function () {
        send({ type: 'diag', payload: 'Java.perform callback fired, enumerating classes...' });
        var matchedClasses = 0;
        var hookedMethods = 0;
        var totalClasses = 0;

        Java.enumerateLoadedClasses({
        onMatch: function (className) {
            totalClasses++;
            var dominated = false;
            for (var p = 0; p < PREFIXES.length; p++) {
                if (className.indexOf(PREFIXES[p]) === 0) {
                    dominated = true;
                    break;
                }
            }
            if (!dominated) return;

            matchedClasses++;
            send({ type: 'diag', payload: 'Matched class: ' + className });

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
                            hookedMethods++;
                        }
                    } catch (e) {
                        // Some methods can't be hooked (native, abstract) — skip
                    }
                }
            } catch (e) {
                send({ type: 'diag', payload: 'Failed to hook class ' + className + ': ' + e });
            }
        },
        onComplete: function () {
            send({ type: 'diag', payload: 'Enumeration done: ' + totalClasses + ' total classes, ' +
                   matchedClasses + ' matched, ' + hookedMethods + ' methods hooked' });
            send({ type: 'status', payload: 'hooking_complete' });
        }
        });
    });
}

// Wait for Java VM to be available before hooking
function tryHook() {
    try {
        if (Java.available) {
            hookAll();
            return true;
        }
    } catch (e) {
        // Java global not ready yet
    }
    return false;
}

if (!tryHook()) {
    send({ type: 'status', payload: 'waiting_for_java' });
    var poll = setInterval(function () {
        if (tryHook()) {
            clearInterval(poll);
        }
    }, 500);
}
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


_FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"


def _get_device_arch(device=None):
    """Get the CPU architecture of the connected device."""
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "getprop", "ro.product.cpu.abi"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    abi = result.stdout.strip()
    # Map Android ABI to Frida release name
    abi_map = {
        "arm64-v8a": "arm64",
        "armeabi-v7a": "arm",
        "x86_64": "x86_64",
        "x86": "x86",
    }
    arch = abi_map.get(abi)
    if not arch:
        _error_exit(f"Unsupported device architecture: {abi}")
    return arch


def _is_frida_server_running(device=None):
    """Check if frida-server is already running on the device."""
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", "ps | grep frida-server || true"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return "frida-server" in result.stdout


def _is_frida_server_present(device=None):
    """Check if frida-server binary exists on the device."""
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", f"ls {_FRIDA_SERVER_PATH} 2>/dev/null && echo EXISTS || echo MISSING"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return "EXISTS" in result.stdout


def _download_frida_server(arch):
    """Download the correct frida-server binary matching the installed frida version."""
    import frida
    version = frida.__version__
    filename = f"frida-server-{version}-android-{arch}"
    xz_filename = filename + ".xz"
    url = f"https://github.com/frida/frida/releases/download/{version}/{xz_filename}"

    cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "frida-server")
    os.makedirs(cache_dir, exist_ok=True)
    cached_bin = os.path.join(cache_dir, filename)

    if os.path.isfile(cached_bin):
        _info(f"Using cached frida-server: {cached_bin}")
        return cached_bin

    _info(f"Downloading frida-server {version} for {arch}...")
    _info(f"  URL: {url}")
    try:
        xz_path = os.path.join(cache_dir, xz_filename)
        urllib.request.urlretrieve(url, xz_path)
    except Exception as e:
        _error_exit(
            f"Failed to download frida-server: {e}\n"
            f"Download manually from: https://github.com/frida/frida/releases/tag/{version}\n"
            f"Then push to device: adb push <file> {_FRIDA_SERVER_PATH}"
        )

    _info("Extracting...")
    with lzma.open(xz_path, "rb") as xz_f:
        with open(cached_bin, "wb") as out_f:
            out_f.write(xz_f.read())
    os.remove(xz_path)

    _info(f"Cached at: {cached_bin}")
    return cached_bin


def _ensure_frida_server(device=None):
    """Check if frida-server is running on the device; if not, push and start it."""
    if _is_frida_server_running(device):
        _info("frida-server is already running on device")
        return

    _info("frida-server not running on device — setting up...")

    arch = _get_device_arch(device)
    _debug(f"Device architecture: {arch}")

    if not _is_frida_server_present(device):
        local_bin = _download_frida_server(arch)

        _info(f"Pushing frida-server to device...")
        cmd = ["adb"]
        if device:
            cmd += ["-s", device]
        cmd += ["push", local_bin, _FRIDA_SERVER_PATH]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            _error_exit(f"Failed to push frida-server: {result.stderr.strip()}")

        cmd = ["adb"]
        if device:
            cmd += ["-s", device]
        cmd += ["shell", f"chmod 755 {_FRIDA_SERVER_PATH}"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    else:
        _info("frida-server binary already on device")

    # Start frida-server in background
    _info("Starting frida-server...")
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["shell", f"su -c '{_FRIDA_SERVER_PATH} -D &'"]
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait for it to start
    for i in range(10):
        time.sleep(1)
        if _is_frida_server_running(device):
            _info("frida-server started successfully")
            return
    _error_exit(
        "frida-server failed to start. Your emulator may not be rooted.\n"
        "Use an emulator image without Google Play Store (labelled 'Google APIs' only)."
    )


def _install_apk(apk_path, device=None):
    """Install the APK onto the connected device via ADB, replacing any existing version."""
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += ["install", "-r", apk_path]
    _info(f"Installing {apk_path}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip()
            _error_exit(f"APK install failed: {stderr}")
        _info("APK installed successfully")
    except FileNotFoundError:
        _error_exit("ADB not found on PATH.  Install Android SDK platform-tools.")
    except subprocess.TimeoutExpired:
        _error_exit("APK install timed out (120s).  Check device connection.")


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
            elif payload.get("type") == "status":
                _info(f"Frida status: {payload.get('payload')}")
            elif payload.get("type") == "diag":
                _debug(f"Frida: {payload.get('payload')}")
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
        frida_device.resume(pid)
    except Exception as e:
        _error_exit(
            f"Failed to spawn {package}: {e}\n"
            "Ensure the app is installed and frida-server is running."
        )

    _info("App launched — waiting for Java VM to initialise...")
    time.sleep(5)

    try:
        session = frida_device.attach(pid)
    except Exception as e:
        _error_exit(
            f"Failed to attach to {package} (pid {pid}): {e}\n"
            "The app may have crashed on launch."
        )

    script = session.create_script(script_source)
    script.on("message", on_message)
    script.load()
    _info(f"Instrumentation loaded.  Tracing for {duration} seconds...")

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

    _debug(f"Enriching call graph with {len(edges)} runtime edges...")

    for edge in edges:
        caller_key = edge["caller"]
        callee_key = edge["callee"]

        caller_node = _find_node(caller_key, node_by_norm)
        callee_node = _find_node(callee_key, node_by_norm)

        if caller_node is None:
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
    if partial_label in node_by_norm:
        return node_by_norm[partial_label]

    search = partial_label + "("
    for norm_label, node in node_by_norm.items():
        if norm_label.startswith(partial_label) or search in norm_label:
            return node

    if ";->" in partial_label:
        for norm_label, node in node_by_norm.items():
            if partial_label in norm_label:
                return node

    return None


# ---------------------------------------------------------------------------
# Cross-validation helpers — imported by reachability.py when --dynamic is used
# ---------------------------------------------------------------------------

def build_dynamic_sink_index(trace):
    """
    Build a set of all methods observed as callees in the runtime trace,
    plus a mapping from callee -> list of callers (for evidence reporting).

    Returns:
        observed_methods: set of callee labels (e.g. "Lcom/test/Foo;->bar")
        callee_to_callers: dict mapping callee label -> list of caller labels
    """
    observed_methods = set()
    callee_to_callers = {}

    for edge in trace.get("edges", []):
        callee = edge["callee"]
        caller = edge["caller"]
        observed_methods.add(callee)
        callee_to_callers.setdefault(callee, []).append(caller)

    return observed_methods, callee_to_callers


def is_dynamically_observed(finding, observed_methods):
    """
    Check whether a finding's sink was observed at runtime.

    Matching strategy (mirrors _find_node logic):
      1. Exact match of matched_label against observed methods
      2. Partial match: class+method prefix from the finding against observed callees
      3. Class-only match as fallback
    """
    matched_label = finding.get("matched_label", "")
    raw_class = finding.get("raw_class", "")
    raw_method = finding.get("raw_method", "")

    # Strategy 1: exact match on the full normalised label
    if matched_label:
        for obs in observed_methods:
            if matched_label.startswith(obs) or obs.startswith(matched_label):
                return True
            if (obs + "(") in matched_label:
                return True

    # Strategy 2: class + method from the finding against trace callees
    if raw_class and raw_method:
        dalvik_cls = "L" + raw_class.replace(".", "/") + ";"
        search_key = dalvik_cls + "->" + raw_method
        for obs in observed_methods:
            if search_key in obs or obs.startswith(search_key):
                return True

    # Strategy 3: class-only (any method in that class was called)
    if raw_class:
        dalvik_cls = "L" + raw_class.replace(".", "/") + ";"
        for obs in observed_methods:
            if dalvik_cls in obs:
                return True

    return False


def get_dynamic_callers(finding, callee_to_callers):
    """
    Return the list of runtime callers for a finding's sink, for evidence.
    Uses the same fuzzy matching as is_dynamically_observed.
    """
    matched_label = finding.get("matched_label", "")
    raw_class = finding.get("raw_class", "")
    raw_method = finding.get("raw_method", "")

    callers = []

    for callee, caller_list in callee_to_callers.items():
        matched = False
        if matched_label:
            if (matched_label.startswith(callee) or callee.startswith(matched_label)
                    or (callee + "(") in matched_label):
                matched = True
        if not matched and raw_class and raw_method:
            dalvik_cls = "L" + raw_class.replace(".", "/") + ";"
            search_key = dalvik_cls + "->" + raw_method
            if search_key in callee or callee.startswith(search_key):
                matched = True
        if not matched and raw_class:
            dalvik_cls = "L" + raw_class.replace(".", "/") + ";"
            if dalvik_cls in callee:
                matched = True
        if matched:
            callers.extend(caller_list)

    seen = set()
    unique = []
    for c in callers:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def cross_validate(findings, observed_methods, callee_to_callers):
    """
    Annotate each finding with cross-validation results.

    Reads the static verdict (already set by run_reachability) and the
    dynamic observation, then sets:
        f["dynamic_observed"]           — bool
        f["dynamic_callers"]            — list of runtime caller labels
        f["validation_label"]           — "VALIDATED" | "CONTRADICTION" | None
        f["contradiction_type"]         — "static_no_dynamic" | "dynamic_no_static" | None
        f["contradiction_explanation"]  — human-readable explanation | None
    """
    for f in findings:
        dyn_observed = is_dynamically_observed(f, observed_methods)
        dyn_callers = get_dynamic_callers(f, callee_to_callers) if dyn_observed else []

        f["dynamic_observed"] = dyn_observed
        f["dynamic_callers"] = dyn_callers
        f["validation_label"] = None
        f["contradiction_type"] = None
        f["contradiction_explanation"] = None

        static_verdict = f["verdict"]

        if static_verdict == "UNRESOLVED":
            pass  # no validation possible

        elif static_verdict == "REACHABLE" and dyn_observed:
            # Agreement: both confirm reachability
            f["validation_label"] = "VALIDATED"

        elif static_verdict == "REACHABLE" and not dyn_observed:
            # Contradiction: static says reachable, dynamic did not observe
            f["validation_label"] = "CONTRADICTION"
            f["contradiction_type"] = "static_no_dynamic"
            f["contradiction_explanation"] = (
                "Static CFG found a path to this sink, but it was not exercised during "
                "runtime tracing. This may indicate the path requires specific user "
                "interaction not covered by automated exercising, the path may traverse "
                "a conditionally dead branch, or it may be a static analysis false positive."
            )

        elif static_verdict == "NOT REACHABLE" and dyn_observed:
            # Contradiction: static says unreachable, but runtime observed it
            f["verdict"] = "REACHABLE"
            f["validation_label"] = "CONTRADICTION"
            f["contradiction_type"] = "dynamic_no_static"
            f["contradiction_explanation"] = (
                "No static CFG path was found to this sink, but runtime tracing confirmed "
                "it was executed. This typically indicates reflection, dynamic dispatch, "
                "dynamic class loading, or callback patterns that static analysis cannot "
                "resolve."
            )

        elif static_verdict == "NOT REACHABLE" and not dyn_observed:
            pass  # both agree: not reachable, no special label

    return findings


# ---------------------------------------------------------------------------
# CLI — trace command only
# ---------------------------------------------------------------------------

def main():
    global DEBUG

    parser = argparse.ArgumentParser(
        description="Dynamic Analysis Module — runtime trace capture for the "
                    "Android Reachability Analyzer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Capture a trace (30 seconds, 2000 monkey events)
  python dynamic_analysis.py trace --apk target.apk -o trace.json

  # Then use it with the main tool
  python reachability.py --apk target.apk --findings report.json --dynamic trace.json
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_trace = sub.add_parser("trace", help="Capture a runtime call trace via Frida")
    p_trace.add_argument("--apk", required=True,
                         help="Path to the APK file (package name is extracted automatically)")
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

    args = parser.parse_args()
    DEBUG = getattr(args, "debug", False)

    if args.command == "trace":
        if not os.path.isfile(args.apk):
            _error_exit(f"APK not found: {args.apk}")

        from androguard.misc import AnalyzeAPK
        _info(f"Extracting package name from {args.apk}...")
        apk_obj, _, _ = AnalyzeAPK(args.apk)
        package = apk_obj.get_package()
        if not package:
            _error_exit("Could not extract package name from APK")
        _info(f"Package: {package}")

        _check_adb()
        _ensure_frida_server(device=args.device)
        _install_apk(args.apk, device=args.device)

        capture_trace(
            package=package,
            duration=args.duration,
            output_path=args.output,
            device=args.device,
            monkey_events=args.monkey_events,
            extra_prefixes=args.extra_prefix or None,
        )


if __name__ == "__main__":
    main()
