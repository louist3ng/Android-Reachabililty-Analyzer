# Android Reachability Analyzer

A proof-of-concept Python CLI tool that determines whether vulnerabilities found by MobSF are actually **reachable** from valid Android entry points.

Most scanners flag every pattern match as a finding — but if no execution path connects a user-facing entry point to the vulnerable code, it may not be exploitable. This tool bridges that gap by walking the APK's call graph.

> **⚠️ Disclaimer:** The dynamic analysis feature (`dynamic_analysis.py` and the `--dynamic` flag) is **experimental** and may not work reliably. It depends on Frida, a rooted device or emulator, and specific ADB/Frida version compatibility — any of which can cause failures. Results from dynamic cross-validation may be incomplete or inaccurate and should not be relied upon as a sole source of truth. The static analysis pipeline (`reachability.py` without `--dynamic`) is the stable, primary workflow.

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
5. Reachable findings are checked for false-positive risk (invalid entry points)
6. A triaged Markdown report is generated

**Note:** Only the `code_analysis` section of MobSF reports is parsed. The `android_api` and `manifest_analysis` sections are ignored — `android_api` contains informational API usage patterns rather than specific vulnerabilities, and `manifest_analysis` findings are configuration-level issues that don't map to call-graph nodes.

## Setup

### Core dependencies (required)

```
pip install androguard networkx
```

These power the static call-graph analysis that every run uses.

### MobSF (required — provides the vulnerability findings)

MobSF scans the APK for vulnerabilities. You can either let the tool auto-scan via the MobSF API, or supply a pre-exported JSON report.

- Install and run MobSF: `docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf`
- Grab your API key from the MobSF web UI (REST API Key on the home page)

### Frida (optional — enables runtime cross-validation) — ⚠️ EXPERIMENTAL

> **⚠️ Experimental:** The dynamic analysis feature is experimental and may not work reliably. It has known limitations with certain emulator configurations, Frida version mismatches, and specific APK targets. Use at your own risk — results may be incomplete or inaccurate.

Adding a Frida runtime trace lets the tool cross-validate static results against actual runtime behaviour, labelling findings as `[VALIDATED]` or `[CONTRADICTION]`.

```
pip install frida frida-tools
```

Additional requirements:
- Android emulator or rooted device accessible via ADB
- [frida-server](https://frida.re/docs/android/) running on the device (version must match the `frida` Python package)

## Usage

### Static analysis only

**Option A — Auto-scan with MobSF (recommended):**

```
python reachability.py --apk target.apk --mobsf-url http://localhost:8000 --mobsf-key YOUR_API_KEY --output report.md
```

**Option B — Pre-exported MobSF findings file:**

```
python reachability.py --apk target.apk --findings mobsf_report.json --output report.md
```

### Static + dynamic cross-validation — ⚠️ EXPERIMENTAL

> **⚠️ Experimental:** The dynamic analysis workflow below is experimental and may not work reliably across all environments, devices, or APKs.

**Step 1 — Capture a runtime trace** (run once per APK, reuse across analyses):

```
python dynamic_analysis.py trace --apk target.apk --output trace.json --duration 30
```

The package name is extracted from the APK automatically. The tool then spawns the app via Frida, hooks all methods in the target package, runs Android's `monkey` tool for automated UI exercising, and records caller/callee pairs.

**Step 2 — Run cross-validated analysis** (add `--dynamic` to any static command):

```
python reachability.py --apk target.apk --findings mobsf_report.json --dynamic trace.json --output report.md
```

When `--dynamic` is absent, the tool runs pure static analysis — no change to default behaviour.

## CLI Options

### reachability.py

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
| `--dynamic` | No | - | **(Experimental)** Path to a runtime trace JSON (from `dynamic_analysis.py trace`). Enables cross-validation: labels findings as `[VALIDATED]` or `[CONTRADICTION]`. |

### dynamic_analysis.py trace — ⚠️ EXPERIMENTAL

| Flag | Default | Description |
|---|---|---|
| `--apk` | - | Path to the APK file (package name extracted automatically) |
| `--duration` | `30` | Trace duration in seconds |
| `--monkey-events` | `2000` | Monkey UI events (0 to disable) |
| `--device` | first available | ADB device serial |
| `--extra-prefix` | - | Additional package prefixes to hook (repeatable) |

## Example Output

### Without `--dynamic` (static only)

```markdown
## [REACHABLE] SQL Injection in Login Query - Critical

Sink:             Lcom/test/reachability/SqlActivity;->performLogin()V
Entry Point:      Lcom/test/reachability/SqlActivity;->onCreate(Landroid/os/Bundle;)V
Match Confidence: Exact class + method
Call Chain:       SqlActivity.onCreate -> Lambda.onClick -> SqlActivity.performLogin
Path Length:      3 hops

## [NOT REACHABLE] Contact Exfiltration in Dead Code Path - Critical

Sink:                  Lcom/test/reachability/DeadAdminClient;->exfiltrateContacts()V
Entry Point(s) Checked: 11
Reason:                No path found within 15 hops from any entry point
```

### With `--dynamic trace.json` (cross-validated) — ⚠️ EXPERIMENTAL

```markdown
## [VALIDATED] SQL Injection in Login Query - Critical

Analysis Source:   Confirmed by both static CFG analysis and runtime trace
Sink:              Lcom/test/reachability/SqlActivity;->performLogin()V
Entry Point:       Lcom/test/reachability/SqlActivity;->onCreate(Landroid/os/Bundle;)V
Call Chain:        SqlActivity.onCreate -> Lambda.onClick -> SqlActivity.performLogin
Dynamic Evidence:  Sink observed at runtime, called by: Lambda.onClick

## [CONTRADICTION] Insecure Logging of Credentials - Medium

Analysis Source:   Static CFG path found but sink not exercised during runtime trace
Sink:              Lcom/test/reachability/MainActivity;->logCredentials()V
Dynamic Evidence:  Sink was NOT observed during runtime trace
Contradiction:     Static CFG found a path to this sink, but it was not exercised
                   during runtime tracing...

## [CONTRADICTION] Reflection-based Data Leak - High

Analysis Source:   Exercised at runtime but no static CFG path found
Dynamic Evidence:  Sink observed at runtime, called by: ReflectionHelper.invoke
Contradiction:     No static CFG path was found to this sink, but runtime tracing
                   confirmed it was executed...

## [NOT REACHABLE] Contact Exfiltration in Dead Code Path - Critical

Analysis Source:   Neither static CFG nor runtime trace found a path
```

## Report Verdicts

### Without `--dynamic`

| Verdict | Meaning | Action |
|---|---|---|
| **REACHABLE** | A call chain exists from an entry point to the vulnerable code | Priority — investigate and fix |
| **NOT REACHABLE** | No call chain found within the depth limit | Lower priority — may be dead code |
| **UNRESOLVED** | Finding could not be matched to any call-graph node | Manual review needed |

### With `--dynamic` — ⚠️ EXPERIMENTAL

When a runtime trace is provided, reachable findings gain validation labels:

| Verdict | Meaning | Action |
|---|---|---|
| **VALIDATED** | Both static CFG and runtime trace confirm reachability | Highest confidence — prioritise fix |
| **CONTRADICTION** | Static and dynamic results disagree (see explanation on each finding) | Investigate — may be a static analysis blind spot or a conditionally dead branch |
| **REACHABLE** | Static CFG path exists; no dynamic observation either way | Standard priority — investigate and fix |
| **NOT REACHABLE** | Neither static nor dynamic analysis found a path | Lower priority — likely dead code |
| **UNRESOLVED** | Finding could not be matched to any call-graph node | Manual review needed |

## False Positive Risk Flags

Reachable findings may carry a false-positive risk annotation when the entry point is a **non-exported component with no registered intent filter**. The Android runtime has no mechanism to invoke such a component externally, making the execution path unlikely to be triggerable.

This is the only false-positive check the tool performs. It is a deliberate design decision: the tool only flags potential false positives where it has full information — namely the application manifest. Other signals (permission gates, reflection in the call chain, third-party library sinks) are excluded because they represent exploitability constraints or conditions that cannot be evaluated with sufficient confidence by static analysis alone.

## Sink Matching Strategy

Findings are matched to call-graph nodes using progressively looser strategies:

1. **Exact Dalvik signature** — highest confidence
2. **Exact class + method name**
3. **Line number resolved** — uses MobSF's reported line numbers mapped to the specific method via DEX debug info parsing
4. **Rule-specific bytecode match** — scans method bytecode for API calls/string constants specific to the MobSF rule (e.g., `Log.d` for `android_logging`, `rawQuery` for `android_sql_raw_query`, hardcoded credential patterns for `android_hardcoded`)
5. **Exact class only**
6. **Exact method only** — lowest confidence
7. **No match** — finding becomes UNRESOLVED

Tiers 3 and 4 dramatically improve accuracy over the old "Exact class only" fallback, which often matched the wrong node (e.g., a lambda constructor instead of the actual vulnerable method). Supported rule-specific patterns: `android_hardcoded`, `android_logging`, `android_sql_raw_query`, `android_insecure_ssl`, `android_insecure_random`, `android_aes_ecb`, `android_weak_ciphers`, `android_md5`, `android_sha1`, `android_world_readable`, `android_world_writable`, `android_read_write_external`, `android_ip_disclosure`.

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
| `dynamic_analysis.py` | **(Experimental)** Optional dynamic analysis module (Frida-based trace capture + cross-validation helpers for `--dynamic` flag) |
| `INSTRUCTIONS.md` | Detailed usage guide with troubleshooting |
| `CLAUDE.md` | Guidance for Claude Code when working in this repository |
| `sample_mobsf_findings.json` | Sample MobSF `code_analysis` findings mapped to the test APK |
| `samplereport.md` | Sample output report (pre-generated for reference) |
| `.gitignore` | Excludes APKs, debug logs, generated reports, and session data |

## How Cross-Validation Works — ⚠️ EXPERIMENTAL

> **Note:** This entire cross-validation workflow is experimental and may produce unreliable results.

When `--dynamic` is provided:

1. Static BFS runs first on the Androguard call graph (same as without `--dynamic`)
2. Each finding's sink is checked against the runtime trace observation index
3. Results are compared:
   - **Static REACHABLE + dynamic observed** → `[VALIDATED]`
   - **Static REACHABLE + NOT dynamic observed** → `[CONTRADICTION]` (path may be a dead branch or require specific input)
   - **Static NOT REACHABLE + dynamic observed** → `[CONTRADICTION]` (static analysis blind spot — reflection, dynamic dispatch, etc.)
   - **Static NOT REACHABLE + NOT dynamic observed** → `[NOT REACHABLE]`
4. For contradictions where dynamic observed the sink but static didn't, the runtime edges are merged into the graph and BFS is re-run to attempt path recovery

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
