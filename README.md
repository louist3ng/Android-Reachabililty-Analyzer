# Android Reachability Analyzer

A proof-of-concept Python CLI tool that determines whether vulnerabilities found by static analysis scanners (MobSF, Semgrep) are actually **reachable** from valid Android entry points.

Most scanners flag every pattern match as a finding — but if no execution path connects a user-facing entry point to the vulnerable code, it may not be exploitable. This tool bridges that gap by walking the APK's call graph.

## How It Works

```
                  +-----------+          +------------------+
  APK file ------>| Androguard|--------->|  Call Graph       |
                  +-----------+          |  (37k+ nodes)    |
                                         +--------+---------+
                                                  |
  MobSF/Semgrep  +-----------+                    |
  findings  ----->|  Parser   |---> Sinks          |
                  +-----------+        |           |
                                       v           v
                                 +-----+-----+-----+-----+
                                 |    Bounded BFS         |
                                 |  Entry Points -> Sinks |
                                 +-----+-----+-----------+
                                       |     |
                              REACHABLE   NOT REACHABLE
                                 |
                          FP Risk Checks
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

### Run with MobSF findings
```
python reachability.py --apk target.apk --findings mobsf_report.json --source mobsf --output report.md
```

### Run with Semgrep findings (experimental)
```
python reachability.py --apk target.apk --findings semgrep_findings.json --source semgrep --output report.md
```

## CLI Options

| Flag | Required | Default | Description |
|---|---|---|---|
| `--apk` | Yes | - | Path to the APK file |
| `--findings` | Yes | - | Path to MobSF or Semgrep JSON findings |
| `--source` | No | auto-detect | Force format: `mobsf` or `semgrep` |
| `--output` | No | `report.md` | Output Markdown report path |
| `--max-depth` | No | `15` | Max BFS traversal depth (hops) |
| `--debug` | No | off | Print diagnostic output to stderr |

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
| **MobSF** | Validated | Tested against real MobSF v4 API output (`/api/v1/report_json`) |
| **Semgrep** | Experimental | Parser built from documented schema; not yet tested with real output |

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
- Standard library: `argparse`, `json`, `re`, `collections.deque`

## License

This is a proof-of-concept for educational and research purposes.
