# MobileAg — Complete Session Archive, Prompts & Architecture Reference

> **Session Created**: 2026-09-21  
> **Last Updated**: 2026-09-22  
> **Workspace**: `/home/shambhu/Desktop/Mobile_Ag`  
> **Conversation ID**: `269c1286-20ad-4939-b209-92b23ada18fc`

---

## 1. Verbatim User Prompts & Session Timeline

| Step | Timestamp | User Prompt / Instruction | Objective & Outcome |
| :--- | :--- | :--- | :--- |
| **0** | `2026-09-21 20:51:40` | `analyze the whole codebase in depth and must be in depth` | Executed a 360-degree architectural and source-code audit covering all 7 core subsystems, external dependencies, threat model, and dataflow. Generated artifact: [`mobileag_codebase_in_depth_analysis.md`](file:///home/shambhu/.gemini/antigravity-cli/brain/269c1286-20ad-4939-b209-92b23ada18fc/mobileag_codebase_in_depth_analysis.md). |
| **131** | `2026-09-21 22:14:48` | `+i want like this drag and deog the apk and then so all the things automatically. static , dynamic and all the things automatically` | Built the fully automated drag & drop scanning pipeline. Dropping any `.apk` on the web interface initiates upload, triggers parallel SAST decompilation/analysis, taint tracking, attack-graph generation, and dynamic DAST fuzzing/Frida instrumentation with live telemetry over WebSockets. |
| **395** | `2026-09-21 23:17:34` | `continue` | Diagnosed and optimized JADX decompilation with multi-threading (`-j 4`), `--show-bad-code`, and 90s timeout safety. Fixed SARIF exporter `NoneType` line numbers. Verified real scan on `base.apk` (33MB) yielding 15 verified vulnerabilities and 22 attack surface nodes. Ran full test suite — all 79 tests passed cleanly. |
| **439** | `2026-09-22 11:23:30` | `same all the message and prompt all the things for future use` | Consolidated all user messages, prompts, architecture diagrams, bug fixes, operational commands, and reusable instructions into permanent documentation and artifacts. |

---

## 2. Architecture & Pipeline Overview

```
[ Drag & Drop APK File ] (Anywhere on window or dropzone)
           │
           ▼
[ Frontend: index.html ] ──► POST /api/upload/apk ──► Saves file in ./uploads/
           │
           ▼
[ POST /api/scans/run ] ──► Initializes Scan Session (ACTIVE_SCANS[scan_id])
           │
           ├───────────────────────────────┬──────────────────────────────┐
           ▼                               ▼                              ▼
  [ 1. Ingestion Agent ]          [ 2. 10 Parallel SAST ]        [ 3. Autonomous DAST ]
  • JADX decompile (-j 4)         • Taint Engine (bytecode)      • Detects ADB device / emulator
  • APKTool resource decode       • Secret Scanner (entropy)     • Auto-installs APK via ADB
  • AndroidManifest parser        • Smali Call Graph             • Deploys Frida Root Bypass
  • Framework detector            • Binary Protection (ELF)      • Deploys Frida SSL Unpinning
  • Obfuscation & packer          • Code Reviewer (AST)          • Fuzzes exported Activities
                                  • Dependency CVE Auditor       • Fuzzes deep-link URI schemes
                                  • React Native Scanner         • Post-execution Storage audit
                                  • NSC Network Auditor          • Volatile Heap RAM Forensics
           │                               │                              │
           └───────────────────────────────┴──────────────────────────────┘
                                           │
                                           ▼
                 [ 4. 5-Layer FP Filter & Multi-Model Consensus ]
                   • Reachability & sanitizer verification
                   • Multi-model consensus voting & confidence scoring
                                           │
                                           ▼
                 [ 5. Dynamic Attack Surface Graph (Vis.js / Neo4j) ]
                   • Nodes: App, exported components, deep links, APIs, vulnerabilities
                   • Edges: declares, filters, calls, triggers, violates
                                           │
                                           ▼
                 [ 6. Real-Time Telemetry & Report Assembly ]
                   • Live WebSocket stream to UI (/ws/telemetry)
                   • OASIS SARIF v2.1.0 & JSON reports written to disk
                   • Synthesizes Frida hook scripts and Markdown PoC guides
```

---

## 3. Core System Modules

| Subsystem | Key Files | Responsibility |
| :--- | :--- | :--- |
| **Ingestion** | [`mobileag/ingestion/apk_extractor.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/ingestion/apk_extractor.py)<br>[`mobileag/ingestion/manifest_parser.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/ingestion/manifest_parser.py)<br>[`mobileag/ingestion/framework_detector.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/ingestion/framework_detector.py)<br>[`mobileag/ingestion/obfuscation.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/ingestion/obfuscation.py) | Decompiles APK via JADX & APKTool, parses XML manifest, detects app framework (Native, Flutter, React Native, Unity, Xamarin), and inspects ProGuard/DexGuard. |
| **Static Analysis (SAST)** | [`mobileag/analysis/taint_engine.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/analysis/taint_engine.py)<br>[`mobileag/analysis/secret_scanner.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/analysis/secret_scanner.py)<br>[`mobileag/analysis/call_graph.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/analysis/call_graph.py)<br>[`mobileag/analysis/binary_protection_auditor.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/analysis/binary_protection_auditor.py)<br>[`mobileag/analysis/code_reviewer.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/analysis/code_reviewer.py)<br>[`mobileag/analysis/api_mapper.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/analysis/api_mapper.py) | Executes 10 concurrent analysis engines checking for hardcoded credentials, UXSS WebView sinks, cleartext HTTP, missing stack canaries/NX, API route mapping, and dependency flaws. |
| **False Positive Filtering** | [`mobileag/filters/pipeline.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/filters/pipeline.py)<br>[`mobileag/filters/reachability.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/filters/reachability.py)<br>[`mobileag/filters/consensus_vote.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/filters/consensus_vote.py)<br>[`mobileag/filters/confidence.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/filters/confidence.py) | 5-layer pipeline evaluating reachability, sanitizer validation, multi-model LLM consensus voting, historical memory, and final confidence score calibration. |
| **Dynamic Analysis (DAST)** | [`mobileag/dast/adb_manager.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/dast/adb_manager.py)<br>[`mobileag/dast/intent_fuzzer.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/dast/intent_fuzzer.py)<br>[`mobileag/dast/deeplink_fuzzer.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/dast/deeplink_fuzzer.py)<br>[`mobileag/dast/frida_runner.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/dast/frida_runner.py)<br>[`mobileag/dast/storage_auditor.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/dast/storage_auditor.py)<br>[`mobileag/dast/memory_forensics.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/dast/memory_forensics.py) | Interacts with live Android emulators/devices over ADB. Automates installation, deploys Frida hooks (anti-root cloak, universal SSL unpinning), fuzzes IPC intents, audits SQLite/SharedPreferences, and searches RAM for sensitive tokens. |
| **Reporting & Generation** | [`mobileag/reporting/finding.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/reporting/finding.py)<br>[`mobileag/reporting/sarif_exporter.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/reporting/sarif_exporter.py)<br>[`mobileag/generators/frida_generator.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/generators/frida_generator.py)<br>[`mobileag/generators/poc_generator.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/generators/poc_generator.py) | Generates OASIS SARIF v2.1.0 for CI/CD pipelines, JSON reports, runnable Frida exploit/validation scripts, and Markdown PoC reproduction steps. |
| **Web UI & Telemetry** | [`mobileag/web/app.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/web/app.py)<br>[`mobileag/web/templates/index.html`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/web/templates/index.html) | FastAPI backend serving interactive Dark/Cyber AppSec UI, live WebSocket telemetry (`/ws/telemetry`), Vis.js interactive network graph, and REST endpoints. |

---

## 4. Key Improvements & Bug Fixes Made

### 1. Dynamic Tool Discovery
- **Problem**: Host paths to `jadx` and `apktool` were hardcoded to `/usr/local/bin/jadx`, causing failures on Linux environments where `jadx` is in `/usr/bin/jadx` and `apktool` is under `/var/lib/snapd/snap/bin/apktool`.
- **Fix**: Implemented dynamic resolution via `shutil.which` in [`config/settings.py`](file:///home/shambhu/Desktop/Mobile_Ag/config/settings.py) and [`apk_extractor.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/ingestion/apk_extractor.py).

### 2. High-Performance Decompilation & Timeout Guard
- **Problem**: Large production APKs (e.g. 33MB Meesho APK) caused JADX to hang on obfuscated third-party classes.
- **Fix**: Added `-j 4`, `--show-bad-code`, `--no-res`, and an `asyncio.wait_for(..., timeout=90.0)` timeout guard. If JADX takes longer than 90s, the process safely proceeds with the extracted sources and complete Smali disassembly.

### 3. Real Orchestration in Background Telemetry Worker
- **Problem**: The web telemetry worker was previously simulating hardcoded mock stages.
- **Fix**: Wired [`live_scan_telemetry_worker`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/web/app.py#L1533) directly to [`Orchestrator.scan`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/core/orchestrator.py#L86). Real discovered vulnerabilities, components, deep links, and telemetry events are pushed over WebSocket and added to `ACTIVE_SCANS[scan_id]` and the attack-surface graph.

### 4. Robust Autonomous DAST Bridge
- **Problem**: If no ADB device was attached, scans previously threw errors or stalled.
- **Fix**: Added device availability detection (`adb_manager.list_devices()`). If an emulator is connected, DAST executes automatically (install, root bypass, SSL unpinning, intent fuzzing, storage/memory audit). If no device is attached, it completes SAST/Taint cleanly and gracefully informs the user via telemetry that connecting an emulator will trigger live DAST.

### 5. SARIF Exporter NoneType Line Numbers
- **Problem**: `int(f_line)` threw a `TypeError` if `line_number` was `None`.
- **Fix**: Sanitized `f_line` with fallback to line `1` in [`sarif_exporter.py`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/reporting/sarif_exporter.py).

### 6. Seamless Drag-and-Drop UX
- **Problem**: Dropping a file required navigating menus to find the scan result.
- **Fix**: Updated [`index.html`](file:///home/shambhu/Desktop/Mobile_Ag/mobileag/web/templates/index.html) so that dropping an APK anywhere uploads the file, triggers `/api/scans/run`, loads the scan into `currentScan`, switches to the `surface` view, and renders live KPI updates and graph nodes as they are discovered.

---

## 5. Operations Manual — How to Run & Use

### Start the Web Application
```bash
python -m mobileag.cli web --host 127.0.0.1 --port 8080
```
- Open in browser: `http://127.0.0.1:8080`
- Live WebSocket: `ws://127.0.0.1:8080/ws/telemetry`

### Automated Drag & Drop Usage
1. Open the web dashboard in Chrome, Firefox, or any modern browser.
2. Drag and drop any `.apk` file directly onto the dashboard window.
3. Watch the real-time progress:
   - Extraction & manifest parsing
   - 10 parallel static analysis engines
   - Discovered components and vulnerabilities appearing on the Vis.js graph
   - Live DAST execution (if an emulator/device is connected via `adb devices`)
   - Completed audit report with CVSS scores, remediation, and SARIF download

### Run the Full Test Suite
```bash
pytest
```
*Expected result: 79 passed.*

### Run CLI Scans Directly
```bash
# Static + Taint audit
python -m mobileag.cli scan uploads/base.apk --output ./output

# With Dynamic DAST & Root/SSL Bypass (requires ADB device)
python -m mobileag.cli scan uploads/base.apk --dast --bypass-root --bypass-ssl
```

---

## 6. Reusable Prompts for Future Extensions

Save these prompts to quickly trigger specialized development workflows in future sessions:

### Prompt A: Adding iOS / IPA Dynamic Analysis & Objection Hooks
```markdown
Extend MobileAg's dynamic analysis module to support iOS (IPA) runtime instrumentation:
1. Connect mobileag/analysis/ios_analyzer.py to the web dashboard telemetry worker.
2. Implement an Objection / Frida runner for jailbroken iOS devices via USB (usbmuxd).
3. Add keychain forensics, NSUserDefaults auditing, and ATS cleartext traffic detection.
4. Verify all tests pass with pytest.
```

### Prompt B: Multi-Device ADB Fleet Auto-Fuzzing
```markdown
Enhance MobileAg's ADB manager to support concurrent parallel testing across a fleet of devices:
1. Support distributing activities across multiple emulator serials (e.g. emulator-5554, emulator-5556).
2. Aggregate logcat crashes and memory dumps into a unified timeline.
3. Update the DAST frontend tab in index.html to show multi-device selector cards with live screenshots.
```

### Prompt C: Continuous CI/CD GitHub Action Pipeline
```markdown
Create a GitHub Actions workflow (.github/workflows/security-scan.yml) for MobileAg:
1. Run headless SAST, Taint, and Secret scanning on every pull request that modifies mobile code.
2. Export the result in OASIS SARIF v2.1.0 format and upload it to GitHub Security tab (CodeQL).
3. Fail the PR if any CRITICAL or HIGH severity findings are confirmed.
```
