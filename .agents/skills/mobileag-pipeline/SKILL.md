---
name: mobileag-pipeline
description: Run and test the MobileAg dashboard and authorized mobile-analysis pipeline.
---

# MobileAg runbook

## Start locally

```bash
python -m mobileag.cli web --host 127.0.0.1 --port 8080
```

Open the printed URL and enter the session token printed in the terminal using the labelled connection form. API routes require bearer authentication; WebSockets authenticate with an initial JSON token message. Do not put tokens in URLs or durable evidence.

## Scanning

Upload an APK/IPA through the dashboard. Uploads have opaque names, ZIP validation and size limits. Drag-and-drop starts static analysis, not automatic device selection or bypass hooks. Missing files are errors, never demo scans.

`python -m mobileag.cli scan --apk owned.apk --offline --output ./output` enforces no LLM/OSV networking for that scan. Install JADX and APKTool for Android decompilation. Failures are reported as incomplete scans rather than successful clean results.

## Explicit dynamic scope

- Set `MOBILEAG_ALLOWED_DEVICES` to exact authorized serials before starting the server.
- Remote ADB connection targets also need `MOBILEAG_ALLOWED_CONNECT`.
- Explicitly select the device; never choose the first connected device implicitly.
- Frida requires the optional native dependency, matching device server and an already running app. Workbench execution verifies initialization and then detaches; it does not leave persistent hooks or prove an exploit.
- Automatic root/SSL bypass flags are rejected. Root/shell diagnostics are not ordinary-app exploitation proof.
- API replay requires exact `MOBILEAG_ALLOWED_ORIGINS`; private destinations additionally require `MOBILEAG_ALLOW_PRIVATE_TARGETS=1`. Redirects are not followed.

## Tests

```bash
python -m pytest -q
```

Run the full suite after changes. Device commands and providers must be mocked; use synthetic files and researcher-controlled loopback listeners. Regression tests live in `tests/test_security_regressions.py`. Do not weaken negative controls to restore old misleading success statuses.

See `docs/audit-2026-10-05/FIX_STATUS.md` for validation and limitations. The archived pre-fix scripts/results describe the old working tree, not current behavior.

## Current isolated web workflow

Web static analysis requires Linux bubblewrap and an ordinary-user systemd manager. Settings → Check local readiness probes actual namespace/cgroup execution without contacting a target. No unsafe fallback; use a trusted direct APKTool JAR when a snap wrapper cannot run in the sandbox. Web jobs are always offline; cloud review needs an explicitly approved CLI flow or a separately designed broker.

Settings → Authorized scope persists exact actions/package/device/origin/method restrictions, narrowed by server environment ceilings. Without a saved policy, the web product is static-only. Root, shell, install and Frida authorization is explicitly device-wide. History provides cancellation, immutable-original retry and preview/confirmed evidence deletion; original uploads are preserved.

See `docs/product-security-review-2026-10-05/TRANSFORMATION_STATUS.md` for current gates. Optional process/browser acceptance scripts are separate from mocked unit tests; do not present either as current ordinary-app exploitation proof.
