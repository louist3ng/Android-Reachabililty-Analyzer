# Android Reachability Analyzer

A proof-of-concept Python CLI tool that determines whether vulnerabilities found by static analysis scanners (MobSF, Semgrep) are actually **reachable** from valid Android entry points.

Most scanners flag every pattern match as a finding — but if no execution path connects a user-facing entry point to the vulnerable code, it may not be exploitable. This tool bridges that gap by walking the APK's call graph.

## How It Works

```
                                           +------------------+
                  +-----------+            |  Call Graph       |
  APK file ------>| Androguard|----------->|  (37k+ nodes)    |
                  +-----------+            +--------+---------+
                                                    |
                  +-----------+                     |
  MobSF/Semgrep  |  Parser   |---> Sinks           |
  findings  ----->|           |        |            |
                  +-----------+        v            v
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
3. Each scanner finding is matched to a call-graph node using a multi-tier strategy
4. **Bounded BFS** determines if a path exists from any entry point to each sink
5. Reachable findings are annotated with false-positive risk flags
6. A triaged Markdown report is generated

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

### Option 2: Pre-generated findings file

If you already have a MobSF or Semgrep JSON report:

```
python reachability.py --apk target.apk --findings mobsf_report.json --output report.md
```

### Run with Semgrep findings (experimental)
```
python reachability.py --apk target.apk --findings semgrep_findings.json --source semgrep --output report.md
```

## CLI Options

| Flag | Required | Default | Description |
|---|---|---|---|
| `--apk` | Yes | - | Path to the APK file |
| `--findings` | Conditional | - | Path to MobSF or Semgrep JSON findings. Not required when using `--mobsf-url`. |
| `--source` | No | auto-detect | Force format: `mobsf` or `semgrep` |
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

## [UNRESOLVED] Clipboard Data Access - Warning

Raw Finding:       com.example.utils.ClipHelper.getClipData
Reason:            Sink method could not be matched to any call graph node
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

## Supported Findings Formats

| Source | Status | Notes |
|---|---|---|
| **MobSF (auto-scan)** | Validated | Uploads APK, triggers scan, fetches report via MobSF REST API. Tested against MobSF v4. |
| **MobSF (file)** | Validated | Accepts pre-exported JSON from `/api/v1/report_json` or hand-crafted format. |
| **Semgrep** | Experimental | Parser built from documented schema; not yet tested with real output. |

## Repository Contents

| File | Description |
|---|---|
| `reachability.py` | Main CLI tool (single file, no framework dependencies) |
| `INSTRUCTIONS.md` | Detailed usage guide with troubleshooting |
| `sample_mobsf_findings.json` | Sample MobSF findings mapped to the test APK |
| `sample_semgrep_findings.json` | Sample Semgrep findings (hand-crafted) |
| `reachability-apk-v2.apk` | Test APK with intentional vulnerabilities and dead code |
| `report.md` | Sample output report |

## Limitations

- **Static analysis only** — no runtime behavior or dynamic class loading
- **No taint tracking** — checks reachability, not data flow
- **Obfuscated APKs** — ProGuard/R8 reduces match rates
- **Reflection / JNI** — paths through reflection may be incomplete
- **Single APK only** — split APKs and app bundles not supported

## Tech Stack

- **Python 3.8+**
- **[Androguard](https://github.com/androguard/androguard)** — APK parsing, DEX bytecode analysis, call graph generation
- **[NetworkX](https://networkx.org/)** — directed graph traversal (bounded BFS)
- **[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)** (optional) — automated vulnerability scanning via REST API
- Standard library: `argparse`, `json`, `re`, `collections.deque`, `urllib`

## License

This is a proof-of-concept for educational and research purposes.
