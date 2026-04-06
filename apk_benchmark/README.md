# APK Benchmark

Benchmarks the reachability analyzer across BFS depths 5, 10, 15, 20, 25, and 30 to show how depth affects verdict counts and analysis time.

The first run triggers a full MobSF scan and saves the findings to disk. All subsequent depth runs reuse the saved findings JSON, so MobSF is only contacted once.

## Usage

```bash
python apk_benchmark/benchmark_reachability.py \
  --apk target.apk \
  --mobsf-url http://localhost:8000 \
  --mobsf-key YOUR_API_KEY
```

## Output

A folder is created inside `apk_benchmark/` named after the APK (e.g. `apk_benchmark/target/`) containing:

| File | Description |
|---|---|
| `mobsf_findings.json` | MobSF findings saved from the first run |
| `depth_5.md` ... `depth_30.md` | Full reachability report for each depth |
| `summary.md` | Markdown table comparing verdict counts and timing across all depths |

The summary table notes that the first depth row's time includes MobSF scan overhead; the remaining rows reflect only static analysis time.
