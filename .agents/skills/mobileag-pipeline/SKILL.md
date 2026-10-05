---
name: mobileag-pipeline
description: >-
  Operational runbook and testing procedures for MobileAg automated mobile security scanning.
  Use when running the web dashboard, executing automated drag-and-drop SAST/DAST scans,
  connecting ADB emulators for Frida instrumentation, or validating the 79-test test suite.
---

# MobileAg Automated Scanning Pipeline Runbook

## 1. Running the Web Application
Launch the dashboard server with live WebSocket telemetry:
```bash
python -m mobileag.cli web --host 127.0.0.1 --port 8080
```
- Web UI: `http://127.0.0.1:8080`
- Telemetry endpoint: `ws://127.0.0.1:8080/ws/telemetry`

## 2. Automated Drag-and-Drop Workflow
- Dragging any `.apk` onto the browser window triggers `uploadApkFile(file, true)` in `index.html`.
- Uploads to `POST /api/upload/apk` saving in `./uploads/`.
- Automatically calls `POST /api/scans/run` with `auto_dast: true`, `auto_taint: true`, `bypass_root: true`, `bypass_ssl: true`.
- Automatically redirects to the attack surface view (`surface`) and streams real-time telemetry over WebSockets.

## 3. Dynamic Analysis (DAST) & Frida Instrumentation
- Verify device connection: `adb devices`.
- MobileAg auto-detects rooted emulators (AVD, Genymotion, Corellium) and deploys:
  - Universal SSL/TLS unpinning (`frida_runner.generate_unpinning_script()`)
  - Anti-root & emulator detection cloaking (`frida_runner.generate_root_bypass_script()`)
  - Activity & Deep Link fuzzing (`intent_fuzzer.run_full_dast_suite()`)
- If no device is connected, the pipeline gracefully degrades to complete SAST & Taint analysis without hanging.

## 4. Test Suite Execution
Always verify changes across the full 79-test suite:
```bash
pytest
```
