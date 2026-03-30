# Android Reachability Analyzer

A proof-of-concept Python CLI tool that determines whether vulnerabilities found by MobSF are actually **reachable** from valid Android entry points.

Most scanners flag every pattern match as a finding — but if no execution path connects a user-facing entry point to the vulnerable code, it may not be exploitable. This tool bridges that gap by walking the APK's call graph.

## How It Works

```
                                           +------------------+
                  +-----------+            |  Call Graph       |
  APK file ------>| Androguard|----------->|  (37k+ nodes)    |
                  +-----------+            +--------+---------+
                                                    |
                  +-----------+            +--------+---------+
  MobSF          |  Parser   |---> Sinks  | Runtime Trace    |  (optional)
  code_analysis-->| (code     |        |   | (Frida edges)    |
                  |  analysis)|        |   +--------+---------+
                  +-----------+        |            |  merge
        ^                        +-----+------+-----+-----+
        |                        |     Bounded BFS         |
  [auto-scan]                    |  Entry Points -> Sinks  |
        |                        +-----+------+-----------+
  +-----------+                        |      |
  | MobSF API |               REACHABLE   NOT REACHABLE
  | (optional)|                    |
  +-----------+             FP Risk Checks
                                   |
                            Markdown Report
```

1. **Androguard** parses the APK and builds a directed call graph using **NetworkX**
2. Entry points are extracted from the manifest (Activities, Services, Receivers, Providers)
3. Each MobSF `code_analysis` finding is matched to a call-graph node using a multi-tier strategy
4. **Bounded BFS** determines if a path exists from any entry point to each sink
5. Reachable findings are annotated with false-positive risk flags
6. A triaged Markdown report is generated

**Note:** Only the `code_analysis` section of MobSF reports is parsed. The `android_api` and `manifest_analysis` sections are ignored — `android_api` contains informational API usage patterns rather than specific vulnerabilities, and `manifest_analysis` findings are configuration-level issues that don't map to call-graph nodes.

## Quick Start

### Install dependencies
```
pip install androguard networkx
```

### Option 1: Auto-scan with MobSF (recommended)

No need to manually export findings. The tool uploads the APK, triggers the scan, fetches the report, and runs reachability analysis in one command:

```
python reachability.py --apk target.apk --mobsf-url http://localhost:8000 --mobsf-key YOUR_API_KEY --output report.md
```

Prerequisites: MobSF must be running (e.g. `docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf`).

### Option 2: Pre-generated MobSF findings file

If you already have a MobSF JSON report:

```
python reachability.py --apk target.apk --findings mobsf_report.json --output report.md
```

## CLI Options

| Flag | Required | Default | Description |
|---|---|---|---|
| `--apk` | Yes | - | Path to the APK file |
| `--findings` | Conditional | - | Path to MobSF JSON findings. Not required when using `--mobsf-url`. |
| `--output` | No | `report.md` | Output Markdown report path |
| `--max-depth` | No | `15` | Max BFS traversal depth (hops) |
| `--debug` | No | off | Print diagnostic output to stderr |
| `--mobsf-url` | No | - | MobSF server URL. Enables auto-scan mode (upload, scan, fetch report). |
| `--mobsf-key` | Conditional | - | MobSF REST API key. Required when `--mobsf-url` is set. |
| `--save-findings` | No | - | Save the auto-fetched MobSF report JSON to disk for re-use. |

## Example Output

```markdown
## [REACHABLE] SQL Injection in Login Query - Critical

Sink:             Lcom/test/reachability/SqlActivity;->performLogin()V
Entry Point:      Lcom/test/reachability/SqlActivity;->onCreate(Landroid/os/Bundle;)V
Match Confidence: Exact class + method
Call Chain:       SqlActivity.onCreate -> Lambda.onClick -> SqlActivity.performLogin
Evidence:         Path length: 3 hops

## [NOT REACHABLE] Contact Exfiltration in Dead Code Path - Critical

Sink:                  Lcom/test/reachability/DeadAdminClient;->exfiltrateContacts()V
Entry Point(s) Checked: 11
Reason:                No path found within 15 hops from any entry point

## [UNRESOLVED] Insecure WebView - High

Raw Finding:       com.example.ui.WebHelper.loadUrl
Reason:            Sink method could not be matched to any call graph node
Match Confidence:  No match
```

## Report Verdicts

| Verdict | Meaning | Action |
|---|---|---|
| **REACHABLE** | A call chain exists from an entry point to the vulnerable code | Priority — investigate and fix |
| **NOT REACHABLE** | No call chain found within the depth limit | Lower priority — may be dead code |
| **UNRESOLVED** | Finding could not be matched to any call-graph node | Manual review needed |

## False Positive Risk Flags

Reachable findings may carry annotations to help triage:

- **Permission gate** — Entry point requires a privileged permission
- **Not exported** — Entry point only reachable from within the app
- **Reflection in chain** — Static analysis may not capture the full runtime path
- **Dead component** — No intent filter and unexported
- **Third-party library sink** — Vulnerability is in a library, not app code

## Sink Matching Strategy

Findings are matched to call-graph nodes using progressively looser strategies:

1. **Exact Dalvik signature** — highest confidence
2. **Exact class + method name**
3. **Exact class only**
4. **Exact method only** — lowest confidence
5. **No match** — finding becomes UNRESOLVED

## Supported Findings

| Source | Status | Notes |
|---|---|---|
| **MobSF (auto-scan)** | Validated | Uploads APK, triggers scan, fetches report via MobSF REST API. Tested against MobSF v4. |
| **MobSF (file)** | Validated | Accepts pre-exported JSON from `/api/v1/report_json` or hand-crafted format. |

Only the `code_analysis` section is parsed. The `android_api` section (informational API usage) and `manifest_analysis` section (configuration issues) are not used for reachability analysis.

## Repository Contents

| File | Description |
|---|---|
| `reachability.py` | Main CLI tool (single file, no framework dependencies) |
| `dynamic_analysis.py` | Optional dynamic analysis module (Frida-based runtime trace enrichment) |
| `INSTRUCTIONS.md` | Detailed usage guide with troubleshooting |
| `CLAUDE.md` | Guidance for Claude Code when working in this repository |
| `sample_mobsf_findings.json` | Sample MobSF `code_analysis` findings mapped to the test APK |
| `samplereport.md` | Sample output report (pre-generated for reference) |
| `.gitignore` | Excludes APKs, debug logs, generated reports, and session data |

## Dynamic Analysis (Optional)

The static call graph can be enriched with runtime method traces captured via [Frida](https://frida.re/) instrumentation. This closes gaps caused by reflection, dynamic dispatch, unrecognised callbacks, and coroutines — edges that are invisible to static analysis.

### Prerequisites

```
pip install frida frida-tools
```

- Android emulator or rooted device accessible via ADB
- [frida-server](https://frida.re/docs/android/) running on the device (version must match the `frida` Python package)

### Workflow

```
                                  +------------------+
  Device / Emulator               |  Runtime Trace   |
  (app + Frida + monkey) -------->|  (JSON edges)    |
                                  +--------+---------+
                                           |
          Static Call Graph                |  merge
          (Androguard)      +--------------+
               |            |
               v            v
          +----+------------+----+
          |   Enriched Graph     |
          |   (static + runtime) |
          +----------+-----------+
                     |
                Bounded BFS
                     |
              Reachability Report
```

**Step 1 — Capture a runtime trace** (run once per APK, reuse across analyses):

```bash
python dynamic_analysis.py trace --package com.test.reachability --output trace.json --duration 30
```

This spawns the app via Frida, hooks all methods in the target package, runs Android's `monkey` tool for automated UI exercising, and records caller/callee pairs.

**Step 2 — Run enriched analysis:**

```bash
python dynamic_analysis.py enrich --apk target.apk --findings mobsf_report.json --trace trace.json --output report.md
```

**Or combine both steps (fully automated):**

```bash
python dynamic_analysis.py auto --apk target.apk --findings mobsf_report.json --package com.test.reachability --output report.md
```

### Dynamic Analysis CLI Options

| Flag | Command | Default | Description |
|---|---|---|---|
| `--package` | trace, auto | - | Target app package name |
| `--duration` | trace, auto | `30` | Trace duration in seconds |
| `--monkey-events` | trace, auto | `2000` | Monkey UI events (0 to disable) |
| `--device` | trace, auto | first available | ADB device serial |
| `--trace` | enrich | - | Path to runtime trace JSON |
| `--extra-prefix` | trace | - | Additional package prefixes to hook (repeatable) |

All flags from the base tool (`--apk`, `--findings`, `--mobsf-url`, `--mobsf-key`, `--max-depth`, `--debug`, `--output`) are also accepted by the `enrich` and `auto` commands.

The dynamic analysis module (`dynamic_analysis.py`) is fully self-contained. Removing it has no effect on the base tool.

## Tech Stack

- **Python 3.8+**
- **[Androguard](https://github.com/androguard/androguard)** — APK parsing, DEX bytecode analysis, call graph generation
- **[NetworkX](https://networkx.org/)** — directed graph traversal (bounded BFS)
- **[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)** (optional) — automated vulnerability scanning via REST API
- **[Frida](https://frida.re/)** (optional) — runtime method tracing for call graph enrichment
- Standard library: `argparse`, `json`, `re`, `collections.deque`, `urllib`

## License

This is a proof-of-concept for educational and research purposes.
