---
name: mobileag-pipeline
description: Run and test the MobileAg dashboard and authorized mobile-analysis pipeline.
---

# MobileAg runbook

## Start locally

```bash
python -m mobileag.cli web --host 127.0.0.1 --port 8080
```

This starts API-only mode. To enable the optional evidence-first browser Studio, explicitly add `--ui` and open `/ui`. Public HTML/JS assets do not confer API authorization; API requests still require the bearer token and preserve scope gates. Opening the Studio does not start scans or device/network actions.

In API-only mode, use the bearer-authenticated API/CLI clients. With `--ui`, open the printed URL plus `/ui` and enter the session token printed in the terminal using the labelled connection form. WebSockets authenticate with an initial JSON token message. Do not put tokens in URLs or durable evidence.

For API-only read navigation, `python -m mobileag.cli dashboard api --transport curl` uses `MOBILEAG_API_TOKEN` or a private prompt. Do not mistake UI navigation or a connected session for target authorization or execution approval. No browser profile or credentials should be saved.

## Scanning

When the optional Studio is enabled, upload an APK/IPA there. Uploads have opaque names, ZIP validation and size limits. Staging never starts a scan; a separate explicit consent and start action begins static analysis. It never selects a device or enables bypass hooks. Missing files are errors, never demo scans.

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

## Web dashboard

Launch the dashboard via `python -m mobileag.cli web --host 127.0.0.1 --port 8080` and open the printed URL. The dashboard connects via the session token displayed in the terminal. API routes require bearer authentication; WebSockets authenticate with an initial JSON token message.
