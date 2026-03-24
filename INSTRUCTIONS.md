# Android Reachability Analyzer - Usage Instructions

## Overview

The Android Reachability Analyzer is a proof-of-concept static analysis tool that bridges the gap between vulnerability scanning and exploitability assessment for Android applications. It is built on the following core technologies:

### Androguard
[Androguard](https://github.com/androguard/androguard) is a Python framework for reverse-engineering Android applications. In this tool, Androguard serves as the primary APK ingestion layer. It parses the compiled Dalvik Executable (DEX) bytecode within an APK, extracts the Android manifest (which declares all application components and their properties), and constructs a static call graph representing every method-to-method invocation within the application. The call graph is the foundational data structure upon which all reachability analysis is performed.

### NetworkX
[NetworkX](https://networkx.org/) is a Python library for the creation, manipulation, and study of complex graphs and networks. Once Androguard produces the call graph as a `networkx.DiGraph` (directed graph), this tool leverages NetworkX's graph traversal capabilities to perform bounded breadth-first search (BFS) from Android entry-point nodes to vulnerability sink nodes. NetworkX provides the algorithmic backbone that determines whether a given vulnerability is reachable within a configurable depth limit.

### MobSF (Mobile Security Framework)
[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) is an automated mobile application security testing framework. It performs static and dynamic analysis of Android and iOS applications, producing detailed JSON reports that catalog discovered vulnerabilities, insecure API usage, and code-level weaknesses. This tool integrates with MobSF in two ways:

1. **Auto-scan mode** (`--mobsf-url` + `--mobsf-key`): The tool communicates directly with a running MobSF instance via its REST API. It uploads the APK, triggers a static analysis scan, waits for completion, and fetches the JSON report — all automatically. This eliminates the need to manually export findings.
2. **File mode** (`--findings`): The tool accepts a pre-exported MobSF JSON report (from the API or UI export). This is useful for offline analysis or when re-running against a previously scanned APK.

In both modes, the tool parses the `code_analysis` and `android_api` sections to extract class names, method names, and severity levels for each reported issue.

### How the Technologies Fit Together

The analysis pipeline operates in a linear sequence:

1. **Androguard** parses the APK and produces a directed call graph (via NetworkX) along with parsed manifest metadata.
2. The vulnerability findings are obtained either by **auto-scanning via the MobSF REST API** or by loading a pre-exported **MobSF** findings file. In either case, the findings are parsed into a normalised list of vulnerability sinks, each mapped to a class and method name.
3. Each sink is matched against nodes in the call graph using a multi-tier matching strategy (exact signature, class+method, class-only, method-only).
4. **NetworkX** performs bounded BFS traversal from each Android entry point (exported Activities, Services, Receivers, Providers) toward each matched sink node.
5. The results are enriched with false-positive risk annotations derived from manifest properties (export status, permissions, intent filters) and call-chain characteristics (reflection usage, third-party library origin).
6. A structured Markdown report is generated, triaging all findings into REACHABLE, NOT REACHABLE, and UNRESOLVED categories.

The tool is implemented as a single Python CLI script (`reachability.py`) with no external framework dependencies beyond Androguard and NetworkX. The MobSF API integration uses only Python's standard library (`urllib`), so no additional packages are required for auto-scan mode.

---

## What This Tool Does

`reachability.py` takes an Android APK and a vulnerability findings file (from MobSF)
and determines whether each vulnerability can actually be *reached* from
a real Android entry point (Activity, Service, BroadcastReceiver, ContentProvider).
It outputs a Markdown report showing which findings are **REACHABLE**, **NOT REACHABLE**,
or **UNRESOLVED**, and flags false-positive risks where relevant.

---

## Files in This Folder

| File | Description |
|---|---|
| `reachability.py` | The main CLI tool |
| `sample_mobsf_findings.json` | Sample MobSF findings mapped to the test APK |
| `report.md` | Sample output report (pre-generated for reference) |
| `INSTRUCTIONS.md` | This file |

---

## Prerequisites

### 1. Python 3.8+
Verify with:
```
python --version
```

### 2. Install dependencies
Run once before first use:
```
pip install androguard networkx
```

---

## Preparing Your Inputs

### 1. Get the APK

You need the actual `.apk` file. Common ways to obtain one:

- **From a device:** `adb pull /data/app/com.example.app/base.apk ./target.apk`
- **From an emulator:** Same `adb pull` command
- **From a build:** Use the signed release APK from your `app/build/outputs/apk/` directory
- **From APKMirror/APKPure:** Download the specific version you are testing

### 2. Obtain the Findings

You have three options for providing vulnerability findings to the tool:

#### Option A - MobSF Auto-Scan (Recommended)

The tool can handle the entire MobSF workflow automatically. You only need a running MobSF instance and its API key.

**Prerequisites:**
- MobSF must be running and accessible (e.g. `http://localhost:8000`)
- You need the REST API key (displayed on the MobSF home page, or found in MobSF settings)

**Starting MobSF** (if not already running):
```
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

When you use `--mobsf-url` and `--mobsf-key`, the tool will:
1. Upload the APK to MobSF via `/api/v1/upload`
2. Trigger a static analysis scan via `/api/v1/scan`
3. Wait for the scan to complete (MobSF v4 typically responds synchronously; if not, the tool polls every 5 seconds for up to 5 minutes)
4. Fetch the full JSON report
5. Feed it directly into the reachability analysis pipeline

No manual export or intermediate files are needed. Optionally use `--save-findings` to save the fetched report to disk for future re-use.

#### Option B - MobSF Pre-Exported Findings File

If you prefer to export the MobSF report manually (or want to re-run against a previously saved report):

1. Upload the APK to your MobSF instance (local or hosted)
2. After the scan completes, export the JSON report:
   - **Via API:**
     ```
     curl -X POST "http://localhost:8000/api/v1/report_json" -H "Authorization: <your-api-key>" -F "hash=<apk-hash>" -o mobsf_findings.json
     ```
   - **Via UI:** Click the JSON export button on the scan results page
3. The JSON should contain `code_analysis` and/or `android_api` sections
4. Pass the downloaded file as `--findings mobsf_findings.json`

---

## Running the Tool

### MobSF Auto-Scan (recommended - one command does everything)
```
python reachability.py --apk target.apk --mobsf-url http://localhost:8000 --mobsf-key YOUR_API_KEY --output report.md
```

### MobSF Auto-Scan with saved report (for re-runs without re-scanning)
```
python reachability.py --apk target.apk --mobsf-url http://localhost:8000 --mobsf-key YOUR_API_KEY --save-findings mobsf_report.json --output report.md
```

### Pre-exported findings file (auto-detects format)
```
python reachability.py --apk target.apk --findings mobsf_findings.json --output report.md
```

### All Command-Line Options

```
python reachability.py --apk target.apk --mobsf-url http://localhost:8000 --mobsf-key YOUR_API_KEY --output report.md --max-depth 15
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--apk` | Yes | - | Path to the APK file |
| `--findings` | Conditional | - | Path to MobSF JSON findings. Not required when using `--mobsf-url`. |
| `--output` | No | `report.md` | Output path for the Markdown report |
| `--max-depth` | No | `15` | Max BFS traversal depth (hops) |
| `--debug` | No | off | Print detailed diagnostic output to stderr |
| `--mobsf-url` | No | - | MobSF server URL (e.g. `http://localhost:8000`). Enables auto-scan mode. |
| `--mobsf-key` | Conditional | - | MobSF REST API key. Required when `--mobsf-url` is set. |
| `--save-findings` | No | - | Save the auto-fetched MobSF report JSON to this file path for re-use. |

### Flag Descriptions

#### `--apk` (required)

The absolute or relative file path to the Android APK you want to analyze. This is the compiled application package that Androguard will parse to extract the Dalvik bytecode, application manifest, and call graph. The APK must be a valid, unmodified `.apk` file. Split APKs (`.xapk`, `.apks`) and Android App Bundles (`.aab`) are not supported; you must provide a single consolidated APK.

Example:
```
--apk ./builds/com.example.banking-v2.3.1.apk
```

#### `--findings` (conditional - required unless `--mobsf-url` is used)

The absolute or relative file path to the MobSF JSON findings file. This file contains the list of vulnerabilities, weaknesses, and insecure API usages that the tool will attempt to match against the APK's call graph. The file must be valid JSON containing `code_analysis` and/or `android_api` top-level keys, where each sub-key represents a rule with a `severity`, `metadata`, and `files` block.

If the file is empty, malformed, or does not match the expected MobSF format, the tool will exit with an error.

This flag is not required when `--mobsf-url` is used, because the tool fetches the findings directly from MobSF. If both `--findings` and `--mobsf-url` are provided, `--mobsf-url` takes precedence and `--findings` is ignored.

Example:
```
--findings ./scans/mobsf_report_2026-03-23.json
```

#### `--output` (optional)

The file path where the Markdown report will be written. If the file already exists, it will be overwritten. If the parent directory does not exist, the tool will fail with a file-write error. The report contains all findings grouped by verdict (REACHABLE, NOT REACHABLE, UNRESOLVED) with call chains, match confidence levels, and false-positive risk annotations.

When omitted, the report is written to `report.md` in the current working directory.

Example:
```
--output ./reports/banking_app_reachability_2026-03-23.md
```

#### `--max-depth` (optional)

Controls the maximum number of hops (method-to-method calls) that the bounded breadth-first search (BFS) traversal will follow when attempting to find a path from an entry point to a sink node. This is the primary performance and accuracy tuning parameter.

- A **lower value** (e.g., 8-10) produces faster results but may miss vulnerabilities that sit deep in the call chain, resulting in false NOT REACHABLE verdicts.
- A **higher value** (e.g., 20-25) catches deeper call chains but increases analysis time, particularly on large APKs with 100,000+ nodes in the call graph.
- The **default of 15** is suitable for most applications and covers the majority of real-world call-chain depths.
- Values **above 30** are rarely productive. If a vulnerability requires more than 30 method calls to reach from an entry point, it is unlikely to represent a practical attack path.

The traversal is bounded to prevent the tool from hanging on large call graphs. Without this limit, a full graph traversal on a complex APK could take hours or exhaust available memory.

Example:
```
--max-depth 20
```

#### `--debug` (optional)

Enables detailed diagnostic output printed to stderr. This flag is essential for troubleshooting when the tool reports unexpected results (e.g., all findings showing as NOT REACHABLE when some should be REACHABLE). When enabled, the tool prints:

- **Sample call-graph node labels** (first 10 nodes) showing the exact string format Androguard produces for your APK. This reveals whether the node format matches expectations (e.g., whether the `->` separator is present, whether metadata suffixes like `[access_flags=...]` are appended).
- **Node index statistics** showing how many unique normalised labels were built from the raw graph nodes.
- **Every manifest component** and whether its lifecycle methods were found in the call graph, including the Dalvik class pattern that was searched for.
- **Every sink match attempt** showing the raw class/method from the findings file, which confidence level matched, and the normalised label it resolved to (or NONE if unresolved).
- **Unbounded reachability checks** for NOT REACHABLE findings, indicating whether a path exists beyond the `--max-depth` limit. This distinguishes "genuinely unreachable" from "reachable but too deep."

When omitted, only `[INFO]` and `[WARN]` messages are printed.

Example:
```
python reachability.py --apk target.apk --findings findings.json --debug
```

#### `--mobsf-url` (optional)

The base URL of a running MobSF instance (e.g., `http://localhost:8000`). When this flag is provided, the tool enters **auto-scan mode**: it uploads the APK to MobSF, triggers a static analysis scan, waits for the scan to complete, and fetches the full JSON report — all via the MobSF REST API. This eliminates the need to manually scan the APK and export the findings file.

The MobSF instance must be running and reachable at the specified URL before the tool is invoked. The tool communicates with the following MobSF API endpoints:

- `POST /api/v1/upload` — uploads the APK file
- `POST /api/v1/scan` — triggers the static analysis scan (MobSF v4 typically returns the full report synchronously from this endpoint)
- `POST /api/v1/report_json` — fetches the report if the scan response was asynchronous

If MobSF does not return a scan result synchronously, the tool polls `/api/v1/report_json` every 5 seconds for up to 5 minutes before timing out.

When `--mobsf-url` is provided, the `--findings` flag becomes optional and `--source` is automatically set to `mobsf`.

Example:
```
--mobsf-url http://localhost:8000
--mobsf-url http://192.168.1.50:8000
```

#### `--mobsf-key` (conditional - required when `--mobsf-url` is set)

The REST API key for authenticating with the MobSF instance. This key is displayed on the MobSF home page when you first access the web UI, and can also be found in the MobSF settings.

The API key is sent as an `Authorization` header with every request to the MobSF API. If the key is invalid or missing, MobSF will return a 401 error and the tool will exit.

Example:
```
--mobsf-key 091488ca5d4b61f5ca5340478c060d668d78db5d1d80e0bd247a5b9c0a06b554
```

#### `--save-findings` (optional)

When using auto-scan mode (`--mobsf-url`), this flag saves the raw MobSF JSON report to the specified file path. This is useful for:

- **Re-running the analysis** with different `--max-depth` settings without re-uploading and re-scanning the APK
- **Archiving** the MobSF report alongside the reachability report for documentation purposes
- **Debugging** the MobSF parser by inspecting the raw JSON structure

The file is written after the scan completes and before the reachability analysis begins. If the file already exists, it will be overwritten.

When `--mobsf-url` is not used, this flag has no effect.

Example:
```
--save-findings ./scans/mobsf_raw_report_2026-03-23.json
```

### Example Commands

```
# Auto-scan with MobSF (recommended - one command does everything)
python reachability.py --apk target.apk --mobsf-url http://localhost:8000 --mobsf-key YOUR_API_KEY --output report.md

# Auto-scan with MobSF and save the raw report for re-use
python reachability.py --apk target.apk --mobsf-url http://localhost:8000 --mobsf-key YOUR_API_KEY --save-findings mobsf_report.json --output report.md

# Re-run against a previously saved MobSF report (no re-scanning needed)
python reachability.py --apk target.apk --findings mobsf_report.json --output report.md

# Pre-exported MobSF findings, auto-detected format
python reachability.py --apk com.banking.app.apk --findings mobsf_report.json

# Quick test with included sample findings
python reachability.py --apk sample.apk --findings sample_mobsf_findings.json --output test_report.md
```

---

## Reading the Report

The report groups findings into three categories:

### REACHABLE
A path was found from an Android entry point to the vulnerable code within the depth
limit. These are your **priority findings** - an attacker could potentially trigger them.

Each reachable finding shows:
- **Sink:** The vulnerable method in Dalvik notation
- **Entry Point:** The lifecycle method that starts the call chain
- **Match Confidence:** How precisely the finding was matched to a call-graph node
- **Call Chain:** The human-readable path from entry to sink
- **FP Risk flags** (if any) - see below

```
## [REACHABLE] Insecure WebView - High

Sink:         Lcom/example/WebHelper;->loadUrl(...)V
Entry Point:  Lcom/example/MainActivity;->onCreate(...)V
Match Confidence: Exact class + method
Call Chain:   MainActivity.onCreate -> HelperClass.init -> WebHelper.loadUrl
Evidence:     Path length: 3 hops
```

### NOT REACHABLE
No path was found within the depth limit. These are **lower priority** - the vulnerable
code exists but cannot be triggered from any entry point the tool identified.

This could mean:
- The code is truly dead/unreachable
- The path exists but exceeds your `--max-depth` setting (try increasing it)
- The connection happens through reflection or native code that static analysis can't follow

```
## [NOT REACHABLE] Hardcoded Credentials - Medium

Sink:                  Lcom/example/AuthUtil;->getSecret()V
Entry Points Checked:  4
Reason:                No path found within 15 hops from any entry point
```

> **Tip:** If you suspect a false negative, try `--max-depth 25` or `--max-depth 30`.

### UNRESOLVED
The tool could not match the finding to any node in the call graph. This usually means:
- The class/method name in the finding doesn't match the compiled code (obfuscation, ProGuard)
- The finding refers to a configuration issue rather than a specific method
- The scanner reported a file path that doesn't map cleanly to a Dalvik class

```
## [UNRESOLVED] SQL Injection - High

Raw Finding:       com.example.db.QueryBuilder.rawQuery
Reason:            Sink method could not be matched to any call graph node
Match Confidence:  No match
```

---

## Understanding FP Risk Flags

Reachable findings may carry false-positive risk annotations. These do **not** change
the verdict - they flag things for the analyst to verify:

| Flag | What It Means |
|---|---|
| **Permission gate** | The entry point requires a privileged permission (e.g., `INSTALL_PACKAGES`). An attacker would need to hold this permission to trigger the chain. |
| **Not exported** | The entry point has `android:exported="false"`. Only the app itself (or apps with the same UID) can reach it. |
| **Reflection in chain** | The call path passes through `Method.invoke()`, `Class.forName()`, etc. The actual runtime path may differ from what static analysis shows. |
| **Dead component** | The entry point has no intent filter and is not exported. It is unlikely to be triggered externally. |
| **Third-party library sink** | The vulnerable method is in a library package, not the app's own code. Confirm the library version is actually affected. |

---

## Match Confidence Levels

The tool tries to match each finding to a call-graph node using progressively looser strategies:

| Level | What Matched | Confidence |
|---|---|---|
| 1. Exact signature | Full Dalvik method signature | Highest |
| 2. Exact class + method | Class name and method name both matched | High |
| 3. Exact class only | Class matched but specific method wasn't found | Medium |
| 4. Exact method only | Method name matched in a different class | Low |
| 5. No match | Finding becomes UNRESOLVED | - |

---

## Tuning max-depth

| Value | When to Use |
|---|---|
| **8-10** | Fast analysis, only care about shallow/direct attack paths |
| **15 (default)** | Good for most apps, covers typical call chains |
| **20-25** | Large apps with deep framework layers, dependency injection, or heavily layered architectures |
| **30+** | Rarely useful. If a vulnerability requires 30+ hops to reach, it is unlikely to be practically exploitable |

---

## Practical Workflow

### Workflow A: Auto-Scan (recommended)

```
1. Start MobSF (docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf)
      |
      v
2. Get your APK + note the MobSF API key from the web UI
      |
      v
3. Run: python reachability.py --apk target.apk --mobsf-url http://localhost:8000 --mobsf-key KEY
      |
      v
4. Open report.md
      |
      v
5. Triage REACHABLE findings first (check FP Risk flags)
6. Consider raising --max-depth if you have many NOT REACHABLE results
7. Investigate UNRESOLVED findings manually if severity is High/Critical
```

### Workflow B: Pre-Exported Findings

```
1. Get your APK
      |
      v
2. Run MobSF to generate findings JSON
      |
      v
3. Run: python reachability.py --apk target.apk --findings findings.json
      |
      v
4. Open report.md
      |
      v
5. Triage REACHABLE findings first (check FP Risk flags)
6. Consider raising --max-depth if you have many NOT REACHABLE results
7. Investigate UNRESOLVED findings manually if severity is High/Critical
```

---

## What the Sample Findings Cover

### sample_mobsf_findings.json (38 findings, 28 rules)

**code_analysis section (28 rules):**
- SSL/TLS bypass (certificate verification disabled, hostname verifier bypass)
- WebView vulnerabilities (JavaScript enabled, file access, remote debugging, JavaScript interface)
- Hardcoded secrets (API keys, passwords, Firebase server key)
- SQL injection (raw queries with user input)
- Insecure storage (SharedPreferences without encryption, external storage, world-readable files, unencrypted database)
- Weak cryptography (MD5, SHA-1, DES/ECB mode, insecure Random)
- Insecure logging (auth tokens, credit card numbers in logs)
- Intent vulnerabilities (implicit intents, unprotected broadcasts, mutable PendingIntent)
- Component security (fragment injection, deep link validation, intent redirect)
- Code execution risks (Runtime.exec command injection, dynamic code loading via DexClassLoader)
- UI security (tapjacking, clipboard data exposure)
- Configuration (backup enabled, debuggable in release, root detection bypass)
- Path traversal in ContentProvider

**android_api section (10 rules):**
- Clipboard, camera, location, contacts, SMS, telephony, audio access
- Installed package enumeration
- Native code loading
- Reflection usage

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| `Failed to parse APK` | Corrupt or non-standard APK | Verify the APK opens in other tools (e.g. apktool) |
| `Cannot determine findings format` | Unknown JSON structure | Ensure the JSON contains `code_analysis` or `android_api` keys (MobSF format) |
| All findings are UNRESOLVED | Obfuscated APK or class name mismatch | Run with `--debug` to see what the tool searched for vs. what exists in the call graph |
| All findings are NOT REACHABLE | Depth limit too low, or entry points not resolved | Run with `--debug` and check the diagnostic output (see below) |
| Report says "Reachable Beyond Depth Limit: N" | `--max-depth` is too low for this APK | Re-run with `--max-depth 25` or `--max-depth 30` |
| 0 entry points resolved | Manifest components could not be matched to call graph nodes | Run with `--debug` to compare manifest Dalvik class names against actual node labels |
| Very slow analysis | Large APK (100k+ methods) | Normal - call graph construction takes time; wait it out |
| `UnicodeEncodeError` on Windows | Terminal encoding | Run: `set PYTHONUTF8=1` then retry |
| `Cannot connect to MobSF` | MobSF not running or wrong URL | Verify MobSF is running: open the URL in a browser. Check the port number. |
| `MobSF API error 401` | Invalid API key | Copy the API key from the MobSF home page or settings. Ensure no extra spaces. |
| `MobSF API error 400` on upload | APK too large or corrupted | Check the APK file size. MobSF may have upload limits depending on configuration. |
| `MobSF scan did not complete within 300 seconds` | Very large APK or MobSF under heavy load | Check the MobSF web UI for scan status. You can also export the report manually and use `--findings` instead. |
| `--mobsf-key is required` | `--mobsf-url` provided without `--mobsf-key` | Both flags are needed for auto-scan mode. |
| `Either --findings or --mobsf-url is required` | Neither findings source provided | Provide `--findings path/to/findings.json` or `--mobsf-url http://localhost:8000 --mobsf-key KEY` |

### Debugging "All NOT REACHABLE" Results

If the report shows all findings as NOT REACHABLE when you expect some to be REACHABLE, run the tool with `--debug` to diagnose:

```
python reachability.py --apk target.apk --findings findings.json --debug 2> debug_log.txt
```

Or with auto-scan:
```
python reachability.py --apk target.apk --mobsf-url http://localhost:8000 --mobsf-key KEY --save-findings mobsf_report.json --debug 2> debug_log.txt
```

> **Note:** When using `--debug`, Androguard's internal logging (via `loguru`) may also print to stderr, producing very large output (50MB+). The tool's own diagnostic lines are prefixed with `[DEBUG]`, `[INFO]`, or `[WARN]`. You can filter them with: `findstr /B "[" debug_log.txt` (Windows) or `grep "^\[" debug_log.txt` (Linux/macOS).

Then open `debug_log.txt` and check each stage in order:

**Stage 1 - Check the node format.** Look for the "Sample call-graph node labels" section near the top. Verify that the nodes use the expected `Lcom/example/Class;->method(...)V` format. If the format is different, the string matching throughout the tool may fail silently.

**Stage 2 - Check entry point resolution.** Look for "Resolved N entry-point methods from M manifest components". If N is 0, no entry points were found, which means every finding will be NOT REACHABLE regardless of sink matching. The debug log will show each manifest component and the Dalvik class pattern it searched for. Compare these patterns against the sample node labels from Stage 1.

**Stage 3 - Check sink matching.** Look for the "Sink match:" lines. Each finding will show its raw class/method, the confidence level it matched at, and the normalised label it resolved to. If most sinks show "confidence=No match", the class/method names in your findings file do not correspond to classes in the APK (common with obfuscated APKs or when the findings were generated from a different version).

**Stage 4 - Check depth limit.** Look for warnings like "'Finding Title' has a path beyond N hops". This means a path EXISTS in the call graph but the BFS depth limit prevented it from being found. Re-run with a higher `--max-depth` (e.g., 25 or 30). The report itself will also show a "Reachable Beyond Depth Limit" count in the header.

---

## Limitations (POC Scope)

- **Static analysis only** - No runtime behavior, no dynamic class loading resolution
- **No taint tracking** - Checks if code is *reachable*, not whether attacker-controlled data *flows* to the sink
- **Obfuscated APKs** - ProGuard/R8 obfuscation will reduce match rates (more UNRESOLVED findings)
- **Reflection and native code** - Paths through `Method.invoke()` or JNI calls may be incomplete
- **Single APK only** - Split APKs / app bundles not supported
