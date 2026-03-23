#!/usr/bin/env python3
"""
Android Reachability Analyzer - POC
Determines whether known vulnerabilities (from MobSF or Semgrep) can be reached
from valid Android entry points using Androguard's call graph.
"""

import argparse
import json
import os
import sys
import re
from datetime import datetime
from collections import deque

import networkx as nx

# ---------------------------------------------------------------------------
# Global debug flag — set via --debug CLI argument
# ---------------------------------------------------------------------------
DEBUG = False

# ---------------------------------------------------------------------------
# Logging helpers - warnings go to stderr, report goes to the output file
# ---------------------------------------------------------------------------

def warn(msg):
    print(f"[WARN] {msg}", file=sys.stderr)

def info(msg):
    print(f"[INFO] {msg}", file=sys.stderr)

def debug(msg):
    """Only prints when --debug is active."""
    if DEBUG:
        print(f"[DEBUG] {msg}", file=sys.stderr)

def error_exit(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Node normalisation helpers
#
# Androguard's call graph contains two types of node objects:
#   - EncodedMethod  (internal to the APK):
#       str() -> "Lcom/example/Class;->method(...)V [access_flags=0x1] @ 0x1a2b"
#   - ExternalMethod (SDK / framework):
#       str() -> "Lcom/example/Class;->method(...)V"
#
# Neither type implements __eq__ or __hash__, so Python uses object identity.
# This means:
#   1. We must NEVER compare two node objects with == unless they are the
#      exact same Python object from cg.nodes().
#   2. The str() output for EncodedMethod contains trailing noise
#      ([access_flags=...] @ 0x...) that must be stripped before matching.
#
# The functions below build a normalised index once and reuse it everywhere.
# ---------------------------------------------------------------------------

# Regex that strips the trailing " [access_flags=...] @ 0x..." suffix
# produced by EncodedMethod.__str__().  ExternalMethod strings pass through
# unchanged because they lack that suffix.
_STRIP_SUFFIX_RE = re.compile(r"\s+\[access_flags=.*$")

def _normalise_node_label(raw_label):
    """
    Strip Androguard metadata noise from a node's str() representation.
    'Lcom/Foo;->bar()V [access_flags=0x1] @ 0xab' -> 'Lcom/Foo;->bar()V'
    """
    return _STRIP_SUFFIX_RE.sub("", raw_label)

def _build_node_index(cg):
    """
    Build a single, reusable index of call-graph nodes.

    Returns three structures:
      node_by_norm   : { normalised_label : node_object }
      node_obj_to_norm: { id(node_object) : normalised_label }
      norm_to_node_obj: same as node_by_norm (alias for readability)

    Using id() as the dict key avoids reliance on __eq__/__hash__.
    """
    node_by_norm = {}       # normalised str -> node object
    node_obj_to_norm = {}   # id(node) -> normalised str

    for n in cg.nodes():
        norm = _normalise_node_label(str(n))
        node_by_norm[norm] = n
        node_obj_to_norm[id(n)] = norm

    return node_by_norm, node_obj_to_norm

# ---------------------------------------------------------------------------
# Synthetic callback edge injection
#
# Androguard's call graph only contains edges for direct method invocations
# found in the bytecode.  When an Activity registers a click listener like:
#
#     button.setOnClickListener(v -> doSomethingDangerous());
#
# the compiler generates a synthetic lambda class:
#
#     MainActivity$$ExternalSyntheticLambda0
#       <init>(MainActivity)    -- constructor, called from onCreate
#       onClick(View)           -- callback, called by the framework at runtime
#
# The call graph has:   onCreate -> Lambda.<init>
# But NOT:              onCreate -> Lambda.onClick -> doSomethingDangerous
#
# This means any vulnerability triggered by a button press, broadcast
# callback, Runnable.run(), etc. will appear as NOT REACHABLE even though
# the user can trivially trigger it.
#
# The fix: after building the call graph, scan for constructor-call edges
# whose target is a synthetic/anonymous class.  For each one, inject
# synthetic edges from the CALLER of <init> to every callback method on
# that class (onClick, run, call, onReceive, etc.).  This bridges the gap
# that Androguard cannot see statically.
# ---------------------------------------------------------------------------

# Common callback methods that the Android framework invokes at runtime
CALLBACK_METHODS = [
    "onClick", "onLongClick", "onTouch", "onCheckedChanged",
    "onItemClick", "onItemSelected",
    "run",                                    # Runnable
    "call",                                   # Callable
    "accept",                                 # Consumer / BiConsumer
    "apply",                                  # Function
    "onReceive",                              # BroadcastReceiver
    "handleMessage",                          # Handler.Callback
    "onServiceConnected", "onServiceDisconnected",
    "onChanged",                              # Observer / LiveData
    "invoke",                                 # Kotlin lambda
]

def _inject_callback_edges(cg, node_by_norm):
    """
    For every edge  A -> SyntheticClass.<init>,  add synthetic edges
    A -> SyntheticClass.callbackMethod  for each callback method found
    in the call graph.

    Targets:
      - $$ExternalSyntheticLambda  (D8/R8 desugared lambdas)
      - $N  anonymous inner classes (e.g. NetworkActivity$1)
    """
    # Pre-index: class_prefix -> list of (norm_label, node) for callback methods
    callback_index = {}   # "Lcom/test/Foo$1;" -> [(norm, node), ...]
    for norm, node in node_by_norm.items():
        # Only care about inner / synthetic classes
        if "$$" not in norm and "$" not in norm:
            continue
        for cb in CALLBACK_METHODS:
            if f"->{cb}(" in norm:
                # Extract the class part  "Lcom/test/Foo$1;"
                cls_end = norm.find(";->")
                if cls_end == -1:
                    continue
                cls_prefix = norm[:cls_end + 1]   # includes the semicolon
                callback_index.setdefault(cls_prefix, []).append((norm, node))

    if not callback_index:
        debug("No synthetic/anonymous callback methods found in call graph")
        return 0

    # Walk existing edges, find  A -> X.<init>  where X is synthetic/anonymous
    edges_to_add = []
    for src, dst in list(cg.edges()):
        dst_norm = _normalise_node_label(str(dst))
        if "-><init>(" not in dst_norm:
            continue
        # Extract class of the constructor target
        cls_end = dst_norm.find(";->")
        if cls_end == -1:
            continue
        cls_prefix = dst_norm[:cls_end + 1]
        if cls_prefix not in callback_index:
            continue
        # Inject:  src -> each callback method on this class
        for cb_norm, cb_node in callback_index[cls_prefix]:
            if not cg.has_edge(src, cb_node):
                edges_to_add.append((src, cb_node, cb_norm))

    for src, cb_node, cb_norm in edges_to_add:
        cg.add_edge(src, cb_node)
        debug(f"  Injected callback edge: {_normalise_node_label(str(src))}  ->  {cb_norm}")

    info(f"Injected {len(edges_to_add)} synthetic callback edges into call graph")
    return len(edges_to_add)


# ---------------------------------------------------------------------------
# Step 2 - Parse the APK and build the call graph
# ---------------------------------------------------------------------------

def build_call_graph(apk_path):
    """Load the APK with Androguard and return (apk, dalvik, analysis, call_graph)."""
    from androguard.misc import AnalyzeAPK

    info(f"Analyzing APK: {apk_path}")
    try:
        apk, dalvik, analysis = AnalyzeAPK(apk_path)
    except Exception as e:
        error_exit(f"Failed to parse APK: {e}")

    info("Building call graph...")
    cg = analysis.get_call_graph()
    info(f"Call graph built: {cg.number_of_nodes()} nodes, {cg.number_of_edges()} edges")

    # -- Debug: show sample nodes so the user can see the actual format -------
    if DEBUG:
        sample_nodes = list(cg.nodes())[:10]
        debug("--- Sample call-graph node labels (first 10) ---")
        for n in sample_nodes:
            raw = str(n)
            norm = _normalise_node_label(raw)
            debug(f"  raw : {raw}")
            debug(f"  norm: {norm}")
            debug(f"  type: {type(n).__name__}")
            debug("")

    return apk, dalvik, analysis, cg

# ---------------------------------------------------------------------------
# Step 3 - Identify Android entry points from the manifest
# ---------------------------------------------------------------------------

# Lifecycle methods we look for per component type
LIFECYCLE = {
    "activity":  ["onCreate", "onStart", "onResume"],
    "service":   ["onStartCommand", "onBind"],
    "receiver":  ["onReceive"],
    "provider":  ["query", "insert", "update", "delete"],
}

def _dalvik_class(java_class):
    """Convert 'com.example.Foo' -> 'Lcom/example/Foo;'."""
    return "L" + java_class.replace(".", "/") + ";"

def get_entry_points(apk, cg, node_by_norm):
    """
    Parse the manifest for exported components and map them to call-graph nodes.
    Returns a list of dicts with node, label, component metadata.
    """
    entry_points = []

    components = []
    for act in apk.get_activities():
        components.append((act, "activity"))
    for svc in apk.get_services():
        components.append((svc, "service"))
    for rcv in apk.get_receivers():
        components.append((rcv, "receiver"))
    for prv in apk.get_providers():
        components.append((prv, "provider"))

    debug(f"Manifest declares {len(components)} components")

    for comp_name, comp_type in components:
        dalvik_cls = _dalvik_class(comp_name)
        lifecycle_methods = LIFECYCLE.get(comp_type, [])

        exported = _is_exported(apk, comp_name, comp_type)
        perms = _get_component_permission(apk, comp_name, comp_type)
        has_filter = _has_intent_filter(apk, comp_name, comp_type)

        matched_any = False
        for method_name in lifecycle_methods:
            # Search the normalised index — the clean Dalvik signature
            # will not contain the [access_flags...] noise
            for norm_label, node in node_by_norm.items():
                if dalvik_cls in norm_label and f"->{method_name}(" in norm_label:
                    entry_points.append({
                        "node": node,
                        "label": norm_label,
                        "component_name": comp_name,
                        "component_type": comp_type,
                        "exported": exported,
                        "permissions": perms,
                        "has_intent_filter": has_filter,
                    })
                    matched_any = True
                    debug(f"  Entry point matched: {comp_name}.{method_name} -> {norm_label}")
                    break

        if not matched_any:
            warn(f"UNRESOLVABLE: component '{comp_name}' ({comp_type}) - no lifecycle methods found in call graph")
            if DEBUG:
                debug(f"  Looked for class pattern: {dalvik_cls}")
                debug(f"  Lifecycle methods tried: {lifecycle_methods}")

    info(f"Resolved {len(entry_points)} entry-point methods from {len(components)} manifest components")
    return entry_points


def _is_exported(apk, comp_name, comp_type):
    """Best-effort check whether a component is exported."""
    try:
        xml = apk.get_android_manifest_xml()
        tag_map = {"activity": "activity", "service": "service",
                    "receiver": "receiver", "provider": "provider"}
        ns = "{http://schemas.android.com/apk/res/android}"
        for elem in xml.iter(tag_map[comp_type]):
            name = elem.get(f"{ns}name", "")
            if name == comp_name or name.endswith("." + comp_name.split(".")[-1]):
                val = elem.get(f"{ns}exported")
                if val is not None:
                    return val.lower() == "true"
                return len(list(elem.iter("intent-filter"))) > 0
    except Exception:
        pass
    return True

def _get_component_permission(apk, comp_name, comp_type):
    """Return the android:permission attribute of a component, if any."""
    try:
        xml = apk.get_android_manifest_xml()
        tag_map = {"activity": "activity", "service": "service",
                    "receiver": "receiver", "provider": "provider"}
        ns = "{http://schemas.android.com/apk/res/android}"
        for elem in xml.iter(tag_map[comp_type]):
            name = elem.get(f"{ns}name", "")
            if name == comp_name or name.endswith("." + comp_name.split(".")[-1]):
                return elem.get(f"{ns}permission")
    except Exception:
        pass
    return None

def _has_intent_filter(apk, comp_name, comp_type):
    try:
        xml = apk.get_android_manifest_xml()
        tag_map = {"activity": "activity", "service": "service",
                    "receiver": "receiver", "provider": "provider"}
        ns = "{http://schemas.android.com/apk/res/android}"
        for elem in xml.iter(tag_map[comp_type]):
            name = elem.get(f"{ns}name", "")
            if name == comp_name or name.endswith("." + comp_name.split(".")[-1]):
                return len(list(elem.iter("intent-filter"))) > 0
    except Exception:
        pass
    return False

# ---------------------------------------------------------------------------
# Step 4 - Parse findings into sink nodes
# ---------------------------------------------------------------------------

def detect_source(findings_data):
    """Auto-detect whether findings come from MobSF or Semgrep."""
    if isinstance(findings_data, dict):
        if "code_analysis" in findings_data or "android_api" in findings_data:
            return "mobsf"
        if "results" in findings_data:
            return "semgrep"
    return None

def parse_findings(filepath, source_hint=None):
    """Load findings file and return a list of normalised finding dicts."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        error_exit(f"Failed to read findings file: {e}")

    if not data:
        error_exit("Findings file is empty")

    source = source_hint or detect_source(data)
    if source == "mobsf":
        return _parse_mobsf(data), source
    elif source == "semgrep":
        return _parse_semgrep(data), source
    else:
        error_exit("Cannot determine findings format. Use --source mobsf|semgrep.")


def _parse_mobsf(data):
    """
    Parse MobSF findings.  Handles TWO formats:

    FORMAT A - Real MobSF API output (v4.x):
        code_analysis.findings.<rule_id>.files = {"com/path/File.java": "12,34"}
        code_analysis.findings.<rule_id>.metadata.severity = "warning"
        android_api.<rule_id>.files = {"com/path/File.java": "12,34"}

    FORMAT B - Hand-crafted / simplified findings:
        code_analysis.<rule_id>.files = [{"class_name": "...", "method_name": "..."}]
        code_analysis.<rule_id>.severity = "high"
    """
    findings = []

    for section_key in ("code_analysis", "android_api"):
        section = data.get(section_key, {})
        if not isinstance(section, dict):
            continue

        # FORMAT A: real MobSF nests rules under code_analysis.findings
        if section_key == "code_analysis" and "findings" in section and isinstance(section["findings"], dict):
            rules = section["findings"]
        else:
            rules = section

        for rule_id, entry in rules.items():
            if not isinstance(entry, dict):
                continue

            metadata = entry.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}

            # Severity: check metadata first (real MobSF), then top-level (hand-crafted)
            severity = metadata.get("severity", entry.get("severity", entry.get("level", "info")))

            # Title / description
            title = metadata.get("description", rule_id)
            # CWE info from real MobSF reports
            cwe = metadata.get("cwe", "")

            files_block = entry.get("files", {})

            # FORMAT A: files is a dict {"com/path/File.java": "12,34,56"}
            if isinstance(files_block, dict) and files_block:
                # Check if it's a dict-of-strings (real MobSF) vs dict-of-dicts
                first_val = next(iter(files_block.values()))
                if isinstance(first_val, str):
                    # Real MobSF format: {"filepath": "line_numbers"}
                    for filepath, line_nums in files_block.items():
                        raw_class = _path_to_class(filepath)
                        # No method name in real MobSF output — leave blank,
                        # sink matching will fall back to class-only (tier 3)
                        findings.append({
                            "title": title,
                            "severity": _normalise_severity(severity),
                            "sink_signature": "",
                            "raw_class": raw_class,
                            "raw_method": "",
                            "source_file": rule_id,
                            "cwe": cwe,
                            "line_numbers": line_nums,
                        })
                    continue

            # FORMAT B: files is a list of dicts with class_name / method_name
            if isinstance(files_block, list):
                for fentry in files_block:
                    raw_class = ""
                    raw_method = ""
                    if isinstance(fentry, dict):
                        raw_class = fentry.get("class_name", fentry.get("path", ""))
                        raw_method = fentry.get("method_name", "")
                    elif isinstance(fentry, str):
                        raw_class = _path_to_class(fentry)

                    findings.append({
                        "title": title,
                        "severity": _normalise_severity(severity),
                        "sink_signature": "",
                        "raw_class": raw_class,
                        "raw_method": raw_method,
                        "source_file": rule_id,
                        "cwe": cwe,
                    })
                continue

            # FORMAT B fallback: files is a single dict with class_name/method_name
            if isinstance(files_block, dict) and ("class_name" in files_block or "method_name" in files_block):
                findings.append({
                    "title": title,
                    "severity": _normalise_severity(severity),
                    "sink_signature": "",
                    "raw_class": files_block.get("class_name", ""),
                    "raw_method": files_block.get("method_name", ""),
                    "source_file": rule_id,
                    "cwe": cwe,
                })

    return findings


def _parse_semgrep(data):
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        meta = extra.get("metadata", {})
        path = result.get("path", "")
        raw_class = _path_to_class(path)
        raw_method = _extract_method_from_lines(extra.get("lines", ""))

        findings.append({
            "title": meta.get("message", result.get("check_id", "unknown")),
            "severity": _normalise_severity(meta.get("severity", extra.get("severity", "info"))),
            "sink_signature": "",
            "raw_class": raw_class,
            "raw_method": raw_method,
            "source_file": path,
        })
    return findings


def _normalise_severity(s):
    s = str(s).lower().strip()
    # MobSF uses "good" for positive/secure findings — map to Info
    if s == "good" or s == "secure":
        return "Info"
    for level in ("critical", "high", "medium", "low", "info", "warning"):
        if level in s:
            return level.capitalize()
    return "Info"


def _path_to_class(path):
    """Convert 'app/src/main/java/com/example/Foo.java' -> 'com.example.Foo'."""
    path = path.replace("\\", "/")
    for prefix in ("app/src/main/java/", "src/main/java/", "src/"):
        if prefix in path:
            path = path.split(prefix, 1)[1]
            break
    path = re.sub(r"\.(java|kt|smali)$", "", path)
    return path.replace("/", ".")


def _extract_method_from_lines(lines_str):
    """Best-effort extraction of a method name from a code snippet."""
    if not lines_str:
        return ""
    m = re.search(r"(?:void|int|String|boolean|Object|long|byte|char|short|float|double|\w+)\s+(\w+)\s*\(", lines_str)
    return m.group(1) if m else ""

# ---------------------------------------------------------------------------
# Sink matching - try to match each finding to a call-graph node
#
# We match against the NORMALISED label (metadata noise stripped) so that
# "Lcom/Foo;->bar()V [access_flags=0x1] @ 0xab" and "Lcom/Foo;->bar()V"
# are both found by searching for "Lcom/Foo;->bar".
# ---------------------------------------------------------------------------

CONFIDENCE_LEVELS = [
    "Exact signature",
    "Exact class + method",
    "Exact class only",
    "Exact method only",
    "No match",
]

def match_sinks(findings, cg, node_by_norm):
    """
    For each finding, try to match it to a node in the call graph.
    Matching strategy (applied in order, first match wins):
      1. Exact Dalvik signature
      2. Exact class + exact method name
      3. Exact class name only (first node in that class)
      4. Exact method name only (first node with that method name)
      5. No match -> UNRESOLVED
    """
    for f in findings:
        dalvik_cls = _dalvik_class(f["raw_class"]) if f["raw_class"] else ""
        method = f["raw_method"]

        matched_node = None
        matched_label = None
        confidence = "No match"

        # 1) Exact signature against normalised labels
        if f["sink_signature"]:
            if f["sink_signature"] in node_by_norm:
                matched_node = node_by_norm[f["sink_signature"]]
                matched_label = f["sink_signature"]
                confidence = "Exact signature"

        # 2) Exact class + method
        if not matched_node and dalvik_cls and method:
            for norm_label, node in node_by_norm.items():
                if dalvik_cls in norm_label and f"->{method}(" in norm_label:
                    matched_node = node
                    matched_label = norm_label
                    confidence = "Exact class + method"
                    break

        # 3) Exact class only
        if not matched_node and dalvik_cls:
            for norm_label, node in node_by_norm.items():
                if dalvik_cls in norm_label:
                    matched_node = node
                    matched_label = norm_label
                    confidence = "Exact class only"
                    break

        # 4) Exact method only
        if not matched_node and method:
            for norm_label, node in node_by_norm.items():
                if f"->{method}(" in norm_label:
                    matched_node = node
                    matched_label = norm_label
                    confidence = "Exact method only"
                    break

        f["matched_node"] = matched_node
        f["matched_label"] = matched_label or ""
        f["confidence"] = confidence

        debug(f"  Sink match: '{f['raw_class']}.{f['raw_method']}' -> confidence={confidence}, label={matched_label or 'NONE'}")

    return findings

# ---------------------------------------------------------------------------
# Step 5 - Reachability traversal (bounded BFS)
#
# CRITICAL: Androguard node objects (EncodedMethod / ExternalMethod) do NOT
# implement __eq__ or __hash__.  Python falls back to object identity, which
# is fine for set/dict membership (every object has a unique id), but means
# that `neighbor == target_node` ONLY works if both sides are the exact same
# Python object.
#
# To be safe we compare by id() — which is guaranteed unique per object and
# is what Python already uses internally for sets/dicts of these objects.
# ---------------------------------------------------------------------------

def bfs_reachability(cg, source_node, target_node, max_depth):
    """
    Bounded BFS from source_node toward target_node.
    Returns the path as a list of normalised node labels if reachable
    within max_depth hops, or None if not reachable.
    """
    target_id = id(target_node)

    if id(source_node) == target_id:
        return [_normalise_node_label(str(source_node))]

    visited = {id(source_node)}
    # Queue entries: (current_node, path_so_far, current_depth)
    queue = deque([(source_node, [_normalise_node_label(str(source_node))], 0)])

    while queue:
        current, path, depth = queue.popleft()
        if depth >= max_depth:
            continue  # hard cap reached

        for neighbor in cg.successors(current):
            nid = id(neighbor)
            if nid in visited:
                continue
            visited.add(nid)
            neighbor_label = _normalise_node_label(str(neighbor))
            new_path = path + [neighbor_label]
            if nid == target_id:
                return new_path
            queue.append((neighbor, new_path, depth + 1))

    return None


def _check_unbounded_path(cg, source_node, target_node):
    """
    Quick check using NetworkX's has_path (no depth limit).
    Returns True if ANY path exists in the directed graph, regardless of length.
    Used for diagnostics only — helps distinguish 'genuinely unreachable' from
    'reachable but deeper than max_depth'.
    """
    try:
        return nx.has_path(cg, source_node, target_node)
    except (nx.NodeNotFound, nx.NetworkXError):
        return False


def run_reachability(cg, entry_points, findings, max_depth):
    """
    For each finding with a matched sink node, run BFS from every entry point.
    Store the shortest reachable path (fewest hops) or mark NOT REACHABLE / UNRESOLVED.
    """
    for f in findings:
        if f["matched_node"] is None:
            f["verdict"] = "UNRESOLVED"
            f["path"] = None
            f["best_entry"] = None
            f["entry_points_checked"] = 0
            f["unbounded_reachable"] = False
            continue

        best_path = None
        best_entry = None
        unbounded_reachable = False

        for ep in entry_points:
            path = bfs_reachability(cg, ep["node"], f["matched_node"], max_depth)
            if path and (best_path is None or len(path) < len(best_path)):
                best_path = path
                best_entry = ep

        f["entry_points_checked"] = len(entry_points)

        if best_path:
            f["verdict"] = "REACHABLE"
            f["path"] = best_path
            f["best_entry"] = best_entry
            f["unbounded_reachable"] = True
        else:
            # Diagnostic: check if a path exists beyond our depth limit.
            # This tells the user whether increasing --max-depth would help.
            for ep in entry_points:
                if _check_unbounded_path(cg, ep["node"], f["matched_node"]):
                    unbounded_reachable = True
                    debug(f"  '{f['title']}' IS reachable from '{ep['component_name']}' beyond depth {max_depth}")
                    break

            f["verdict"] = "NOT REACHABLE"
            f["path"] = None
            f["best_entry"] = None
            f["unbounded_reachable"] = unbounded_reachable

            if unbounded_reachable:
                warn(f"'{f['title']}' has a path beyond {max_depth} hops - try increasing --max-depth")

    return findings

# ---------------------------------------------------------------------------
# Step 6 - False-positive risk checks (REACHABLE findings only)
# ---------------------------------------------------------------------------

REFLECTION_SIGS = [
    "java/lang/reflect/Method;->invoke",
    "java/lang/reflect/Constructor;->newInstance",
    "java/lang/Class;->forName",
    "java/lang/Class;->getMethod",
    "java/lang/Class;->getDeclaredMethod",
]

def fp_risk_checks(findings, apk):
    """Annotate REACHABLE findings with false-positive risk flags."""
    base_package = apk.get_package()

    for f in findings:
        if f["verdict"] != "REACHABLE":
            continue

        fp_flags = []
        ep = f["best_entry"]

        # Check 1 - Permission gate
        if ep and ep.get("permissions"):
            perm = ep["permissions"]
            fp_flags.append(
                f"Entry point is gated by permission `{perm}` - "
                "exploitability depends on whether the caller holds this permission"
            )

        # Check 2 - Non-exported entry point
        if ep and not ep.get("exported", True):
            fp_flags.append(
                "Entry point is not exported - only reachable from within the same application"
            )

        # Check 3 - Reflection in the call chain
        if f["path"]:
            for node_label in f["path"]:
                if any(sig in node_label for sig in REFLECTION_SIGS):
                    fp_flags.append(
                        "Call chain passes through reflection - "
                        "static analysis may not capture the full runtime path"
                    )
                    break

        # Check 4 - Dead component (no intent filter + unexported)
        if ep and not ep.get("exported", True) and not ep.get("has_intent_filter", False):
            fp_flags.append(
                "Entry point has no intent filter and is unexported - "
                "unlikely to be triggered externally"
            )

        # Check 5 - Third-party library sink
        if f["matched_label"] and base_package:
            sink_pkg = _label_to_package(f["matched_label"])
            base_pkg_slash = base_package.replace(".", "/")
            if sink_pkg and base_pkg_slash not in sink_pkg:
                fp_flags.append(
                    f"Sink resides in a third-party library `{sink_pkg.replace('/', '.')}` - "
                    "confirm whether this vulnerability applies to this version"
                )

        f["fp_flags"] = fp_flags

    return findings


def _label_to_package(label):
    """Extract 'com/example/sub' from 'Lcom/example/sub/Class;->method(...)...'."""
    m = re.match(r"L([\w/]+)/\w+;", label)
    return m.group(1) if m else ""

# ---------------------------------------------------------------------------
# Step 7 - Generate the Markdown report
# ---------------------------------------------------------------------------

def _pretty_label(dalvik_label):
    """Convert 'Lcom/example/Class;->method(...)...' -> 'Class.method'."""
    m = re.match(r"L[\w/]*?(\w+);->(\w+)", dalvik_label)
    return f"{m.group(1)}.{m.group(2)}" if m else dalvik_label


def generate_report(findings, apk_path, source_name, max_depth, output_path):
    reachable   = [f for f in findings if f["verdict"] == "REACHABLE"]
    unreachable = [f for f in findings if f["verdict"] == "NOT REACHABLE"]
    unresolved  = [f for f in findings if f["verdict"] == "UNRESOLVED"]
    fp_flagged  = [f for f in reachable if f.get("fp_flags")]
    # Count findings that ARE reachable but only beyond the depth limit
    beyond_depth = [f for f in unreachable if f.get("unbounded_reachable")]

    lines = []
    lines.append("# Reachability Analysis Report\n")
    lines.append(f"**APK:** {os.path.basename(apk_path)}  ")
    lines.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Findings Source:** {source_name.capitalize()}  ")
    lines.append(
        f"**Total Findings:** {len(findings)} | "
        f"Reachable: {len(reachable)} | "
        f"Not Reachable: {len(unreachable)} | "
        f"Unresolved: {len(unresolved)}  "
    )
    lines.append(f"**Reachable with FP Risk Flags:** {len(fp_flagged)}  ")
    if beyond_depth:
        lines.append(
            f"**Reachable Beyond Depth Limit ({max_depth}):** {len(beyond_depth)} "
            f"- consider re-running with a higher --max-depth  "
        )
    lines.append("")
    lines.append("---\n")

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Warning": 4, "Info": 5}

    for f in sorted(reachable, key=lambda x: severity_order.get(x["severity"], 9)):
        lines.append(f"## [REACHABLE] {f['title']} - {f['severity']}\n")
        lines.append(f"**Sink:** `{f['matched_label']}`  ")
        if f["best_entry"]:
            lines.append(f"**Entry Point:** `{f['best_entry']['label']}`  ")
        lines.append(f"**Match Confidence:** {f['confidence']}  ")
        if f["path"]:
            chain = " -> ".join(_pretty_label(n) for n in f["path"])
            lines.append(f"**Call Chain:** `{chain}`  ")
            lines.append(f"**Evidence:** Path length: {len(f['path'])} hops  ")
        for flag in f.get("fp_flags", []):
            lines.append(f"  **FP Risk:** {flag}  ")
        lines.append("\n---\n")

    for f in sorted(unreachable, key=lambda x: severity_order.get(x["severity"], 9)):
        lines.append(f"## [NOT REACHABLE] {f['title']} - {f['severity']}\n")
        lines.append(f"**Sink:** `{f['matched_label']}`  ")
        lines.append(f"**Entry Point(s) Checked:** {f['entry_points_checked']}  ")
        if f.get("unbounded_reachable"):
            lines.append(
                f"**Reason:** Path exists but exceeds the {max_depth}-hop depth limit. "
                f"Re-run with a higher `--max-depth` value to capture this path.  "
            )
        else:
            lines.append(f"**Reason:** No path found from any entry point (depth limit: {max_depth})  ")
        lines.append(f"**Match Confidence:** {f['confidence']}  ")
        lines.append("\n---\n")

    for f in unresolved:
        lines.append(f"## [UNRESOLVED] {f['title']} - {f['severity']}\n")
        raw = f["raw_class"]
        if f["raw_method"]:
            raw += f".{f['raw_method']}"
        lines.append(f"**Raw Finding:** `{raw}`  ")
        lines.append("**Reason:** Sink method could not be matched to any call graph node  ")
        lines.append(f"**Match Confidence:** {f['confidence']}  ")
        lines.append("\n---\n")

    report = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as out:
        out.write(report)
    info(f"Report written to {output_path}")

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    global DEBUG

    parser = argparse.ArgumentParser(
        description="Android Reachability Analyzer - determine whether known "
                    "vulnerabilities can be reached from valid Android entry points."
    )
    parser.add_argument("--apk", required=True, help="Path to the APK file")
    parser.add_argument("--findings", required=True, help="Path to findings JSON (MobSF or Semgrep)")
    parser.add_argument("--source", choices=["mobsf", "semgrep"], default=None,
                        help="Findings format (auto-detected if omitted)")
    parser.add_argument("--output", default="report.md", help="Output Markdown report path")
    parser.add_argument("--max-depth", type=int, default=15,
                        help="Maximum BFS traversal depth (default: 15)")
    parser.add_argument("--debug", action="store_true",
                        help="Print detailed diagnostic output to stderr")
    args = parser.parse_args()

    DEBUG = args.debug

    if not os.path.isfile(args.apk):
        error_exit(f"APK file not found: {args.apk}")
    if not os.path.isfile(args.findings):
        error_exit(f"Findings file not found: {args.findings}")

    # Step 2 - Parse APK & build call graph
    apk, dalvik, analysis, cg = build_call_graph(args.apk)

    # Build the normalised node index ONCE and share it across all stages
    node_by_norm, node_obj_to_norm = _build_node_index(cg)
    debug(f"Node index built: {len(node_by_norm)} unique normalised labels from {cg.number_of_nodes()} raw nodes")

    # Inject synthetic callback edges for lambdas and anonymous inner classes
    # so that onClick/run/onReceive paths become traversable
    _inject_callback_edges(cg, node_by_norm)

    # Step 3 - Identify entry points
    entry_points = get_entry_points(apk, cg, node_by_norm)
    if not entry_points:
        warn("No entry points resolved - all findings will be NOT REACHABLE")
        if DEBUG:
            debug("--- Dumping all manifest components for diagnosis ---")
            for act in apk.get_activities():
                debug(f"  Activity: {act}  -> dalvik: {_dalvik_class(act)}")
            for svc in apk.get_services():
                debug(f"  Service:  {svc}  -> dalvik: {_dalvik_class(svc)}")
            for rcv in apk.get_receivers():
                debug(f"  Receiver: {rcv}  -> dalvik: {_dalvik_class(rcv)}")
            for prv in apk.get_providers():
                debug(f"  Provider: {prv}  -> dalvik: {_dalvik_class(prv)}")

    # Step 4 - Parse findings & match sinks
    findings, source = parse_findings(args.findings, args.source)
    info(f"Parsed {len(findings)} findings from {source}")
    findings = match_sinks(findings, cg, node_by_norm)

    matched_count = sum(1 for f in findings if f["matched_node"] is not None)
    info(f"Sink matching: {matched_count}/{len(findings)} findings matched to call graph nodes")

    # Step 5 - BFS reachability
    info(f"Running reachability analysis (max depth = {args.max_depth})...")
    findings = run_reachability(cg, entry_points, findings, args.max_depth)

    # Step 6 - FP risk checks
    findings = fp_risk_checks(findings, apk)

    # Step 7 - Generate report
    generate_report(findings, args.apk, source, args.max_depth, args.output)

    # Summary to stderr
    verdicts = {"REACHABLE": 0, "NOT REACHABLE": 0, "UNRESOLVED": 0}
    for f in findings:
        verdicts[f["verdict"]] += 1
    beyond = sum(1 for f in findings if f.get("unbounded_reachable") and f["verdict"] == "NOT REACHABLE")
    info(f"Done - REACHABLE: {verdicts['REACHABLE']}, "
         f"NOT REACHABLE: {verdicts['NOT REACHABLE']}, "
         f"UNRESOLVED: {verdicts['UNRESOLVED']}")
    if beyond:
        info(f"  {beyond} finding(s) ARE reachable beyond depth {args.max_depth} - increase --max-depth to capture them")


if __name__ == "__main__":
    main()
