# MobileAg

Mobile application security review tooling: static heuristics, optional LLM review, explicit device diagnostics, and an authenticated local dashboard.

- Android APK decompilation through JADX/APKTool; iOS IPA static inspection.
- Source, manifest, resource, native-symbol and straight-line taint review candidates.
- Markdown, JSON and SARIF reports with explicit unverified finding status.
- Opt-in, scoped ADB diagnostics and bounded Frida initialization checks.
- Authenticated HTTP/WebSocket APIs, bounded uploads, and scope-controlled HTTP replay.

This is research tooling, not an autonomous exploit verifier. Read the limitations below before relying on a report.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
[ -f .env ] || cp .env.example .env
python -m mobileag.cli web --host 127.0.0.1 --port 8080
```

Python 3.11+ is required. Open the URL printed by the CLI and paste its session token. A fresh token is generated unless `MOBILEAG_API_TOKEN` is configured. Keep it secret; do not place it in URLs or reports. Data lives under the working directory, or `MOBILEAG_DATA_DIR` when configured.

### Static scans

Install `jadx` and `apktool` in PATH for Android analysis, then upload an authorized APK/IPA or run:

```bash
python -m mobileag.cli scan --apk owned.apk --offline --output ./output
python -m mobileag.cli scan --apk owned.apk --offline --format json
python -m mobileag.cli ios --ipa owned.ipa --format markdown
```

`--offline` prevents LLM/OSV requests. The example environment defaults to offline; explicitly set `OFFLINE=false` and configure provider keys only if transmitting source for cloud review is permitted. Reports include Markdown, JSON and SARIF. Decompilation errors fail the scan; they do not produce simulated findings.

### Authorized dynamic testing

Set exact device scope before starting the dashboard:

```bash
export MOBILEAG_ALLOWED_DEVICES=emulator-5554
# Only if connecting over TCP:
export MOBILEAG_ALLOWED_CONNECT=127.0.0.1:5555
```

Choose the device explicitly. Drag-and-drop defaults to static analysis. CLI dynamic testing uses `--package` (not `--pkg`):

```bash
python -m mobileag.cli dast --serial emulator-5554 --package com.example.owned \
  --no-audit-storage --no-audit-memory
```

The Frida workbench requires `pip install -e '.[frida]'`, a matching server on the selected authorized device, and an already running app. It checks script initialization and detaches. Persistent hook orchestration and automatic root/SSL bypass are not implemented; automatic bypass requests fail explicitly. Root/shell observations do not establish ordinary-app exploitability.

### API replay and capture

Outbound API replay is disabled until exact HTTP(S) origins are configured with `MOBILEAG_ALLOWED_ORIGINS` (comma-separated, include non-default ports). Private/local targets also require `MOBILEAG_ALLOW_PRIVATE_TARGETS=1`. Destination DNS is validated and pinned, TLS is verified, responses are bounded, and redirects are not followed.

The optional capture proxy requires `MOBILEAG_PROXY_TOKEN`, accepts only loopback binding, and uses the same destination scope. It supports bounded HTTP framing through h11. **CONNECT/TLS interception is unsupported** and returns 501 rather than pretending to inspect encrypted traffic.

### Optional databases

Configure strong `NEO4J_PASSWORD` and `QDRANT_API_KEY` before `docker compose up -d`. Database ports bind to loopback only. The main scan pipeline does not perform historical learning; feedback must not be interpreted as vector-store synchronization.

## Evidence and limitations

Automated findings are **UNVERIFIED review candidates**, not proven vulnerabilities. Taint detection is a straight-line heuristic, not a complete inter-procedural engine. Symbol presence, exported components, URL paths, shell-readable data and LLM votes do not prove exploitation. Confirmation requires analyst evidence.

The current behavior supersedes the historical capability descriptions above and older architecture/session notes. See [fix status and validation](docs/audit-2026-10-05/FIX_STATUS.md) and the [original review](docs/audit-2026-10-05/REVIEW.md).

## Tests

```bash
python -m pytest -q
```

Tests isolate real device operations and provider credentials. Use synthetic data and controlled loopback targets when adding regressions.
