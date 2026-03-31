# How dynamic_analysis.py Works

This document explains what `dynamic_analysis.py` does, how it fits into the Android Reachability Analyzer, and why it exists.

## The Problem It Solves

The main tool (`reachability.py`) uses **static analysis** to determine if a vulnerability is reachable. It parses the APK's bytecode, builds a call graph, and walks it from entry points to vulnerability sinks. This works well, but static analysis has blind spots:

- **Reflection** — code that calls methods via `Class.forName()` or `Method.invoke()` doesn't produce call graph edges
- **Dynamic dispatch** — interfaces and abstract classes can resolve to different implementations at runtime
- **Callbacks registered at runtime** — e.g. listeners set up in code rather than XML
- **Dynamic class loading** — classes loaded from external DEX files are invisible to static analysis

`dynamic_analysis.py` addresses this by capturing what the app **actually does at runtime**, then comparing those observations against the static results. Where they agree, confidence goes up. Where they disagree, the contradiction is flagged for investigation.

## What It Does (Step by Step)

When you run:
```
python dynamic_analysis.py trace --apk target.apk --output trace.json --duration 30
```

The following happens:

### 1. Extract the package name

The tool uses **Androguard** (the same library used by `reachability.py`) to parse the APK and read the package name from the manifest (e.g. `com.test.reachability`). You don't need to know or type the package name yourself.

### 2. Check for a connected device

It runs `adb devices` to verify that an Android emulator or physical device is connected and responsive.

### 3. Install the APK

It runs `adb install -r target.apk` to install (or reinstall) the APK onto the device. The `-r` flag means it replaces any existing version without uninstalling first.

### 4. Spawn the app with Frida

[Frida](https://frida.re/) is a dynamic instrumentation toolkit. The tool connects to the Frida server running on the device, then **spawns** the target app (starts it fresh). This gives Frida control over the process before any app code runs.

### 5. Inject the instrumentation script

A JavaScript payload is injected into the running app. This script does the following inside the app's process:

- **Enumerates all loaded classes** that belong to the target package (e.g. any class starting with `com.test.reachability`)
- **Hooks every method** in those classes by replacing the method implementation with a wrapper
- When a hooked method is called, the wrapper:
  1. Inspects the Java stack trace to find **who called this method** (the caller)
  2. Records the **(caller, callee)** pair as an edge
  3. Calls the original method so the app behaves normally
- Edges are buffered and sent back to the Python host every 2 seconds

Common noise methods (`toString`, `hashCode`, `equals`, `getClass`) are skipped to reduce clutter.

### 6. Exercise the app with Monkey

Android's built-in [Monkey](https://developer.android.com/studio/test/other-testing-tools/monkey) tool generates pseudo-random UI events (taps, swipes, key presses) to exercise the app automatically. By default it sends 2,000 events. This ensures code paths behind buttons and menus get triggered without manual interaction.

### 7. Wait and collect

The tool waits for the specified duration (default 30 seconds), collecting all the (caller, callee) edges that Frida reports. You can also interact with the app manually during this time to trigger specific flows.

### 8. Save the trace

After the duration expires, the tool:
- Stops the Monkey process
- Detaches Frida from the app
- **Deduplicates** the collected edges (the same call might happen thousands of times, but we only need to know it happened)
- Writes a JSON file containing the unique edges plus metadata (timestamp, duration, device, etc.)

## What the Trace File Looks Like

```json
{
  "package": "com.test.reachability",
  "device": "emulator-5554",
  "timestamp": "2026-03-31T14:22:01",
  "duration_seconds": 30,
  "monkey_events": 2000,
  "total_edge_observations": 12847,
  "unique_edges": 342,
  "edges": [
    {
      "caller": "Lcom/test/reachability/MainActivity;->onCreate",
      "callee": "Lcom/test/reachability/SqlActivity;->performLogin"
    }
  ]
}
```

Each edge says: "at runtime, method A called method B." The labels use Dalvik notation (the format Android bytecode uses internally), which matches the format used by the static call graph.

## How It Integrates with reachability.py

Once you have a `trace.json`, you pass it to the main tool:
```
python reachability.py --apk target.apk --findings report.json --dynamic trace.json --output report.md
```

The main tool then:

1. Runs its normal static analysis (BFS from entry points to sinks)
2. Loads the trace and builds an index of every method that was observed at runtime
3. **Cross-validates** each finding by comparing the static verdict against the runtime observation:

| Static says | Runtime says | Result |
|---|---|---|
| REACHABLE | Observed | **VALIDATED** — high confidence, both agree |
| REACHABLE | Not observed | **CONTRADICTION** — the path might be a dead branch or need specific input |
| NOT REACHABLE | Observed | **CONTRADICTION** — static analysis missed it (reflection, dynamic dispatch, etc.) |
| NOT REACHABLE | Not observed | **NOT REACHABLE** — both agree, likely dead code |

4. For contradictions where runtime saw something static missed, the runtime edges are **merged into the static call graph** and BFS is re-run to try to recover the path

## Two Roles in One File

`dynamic_analysis.py` serves two purposes:

1. **Standalone CLI tool** — run `python dynamic_analysis.py trace --apk ...` to capture a trace
2. **Library imported by reachability.py** — when `--dynamic` is passed, `reachability.py` imports helper functions (`load_trace`, `enrich_call_graph`, `build_dynamic_sink_index`, `cross_validate`) from this module

The module is fully self-contained. Deleting it has no effect on the base tool — the `--dynamic` flag simply becomes unavailable.

## Requirements

- **Frida** (`pip install frida frida-tools`) — the instrumentation framework
- **frida-server** running on the Android device — must match the Python frida version
- **ADB** on your PATH — for device communication and APK installation
- An Android emulator or rooted physical device
