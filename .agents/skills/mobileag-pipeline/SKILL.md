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

For read-only dashboard automation, `python -m mobileag.cli dashboard api --transport curl` and `python -m mobileag.cli dashboard navigate` use `MOBILEAG_API_TOKEN` or a private prompt. Navigation connects through the real token form and visits exact sections; external requests, redirects, writes and real telemetry connections are blocked. No browser profile or credentials are saved. This is dashboard navigation, not target login or execution approval. See `docs/dashboard-self-navigation-2026-10-11/README.md`.

## Scanning

Upload an APK/IPA through the dashboard. Uploads have opaque names, ZIP validation and size limits. Drag-and-drop uploads the artifact; a separate explicit start action begins static analysis. It never selects a device or enables bypass hooks. Missing files are errors, never demo scans.

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

Web static analysis requires Linux bubblewrap and an ordinary-user systemd manager. Settings → Check local readiness probes actual namespace/cgroup execution without contacting a target. No unsafe fallback; use a trusted direct APKTool JAR when a snap wrapper cannot run in the sandbox. Web static jobs are always offline; optional aggregate-metadata review uses the separately gated assessment broker described below.

Settings → Authorized scope persists exact actions/package/device/origin/method restrictions, narrowed by server environment ceilings. Without a saved policy, the web product is static-only. Root, shell, install and Frida authorization is explicitly device-wide. History provides cancellation, immutable-original retry and preview/confirmed evidence deletion; original uploads are preserved.

See `docs/product-security-review-2026-10-05/TRANSFORMATION_STATUS.md` for current gates. Optional process/browser acceptance scripts are separate from mocked unit tests; do not present either as current ordinary-app exploitation proof.

## Guided assessment (primary UI)

Start Assessment: upload → exact APK/API/device scope → select stages → explicitly approve → results. Upload alone never starts testing. API-only stages do not need a fake/implicit device. SAST stays isolated/offline; live stages require static success and a package match. DAST maps the current approved app; exact navigation actions still need review. Install-if-absent refuses replacement and does not request forced runtime permission grants (-g); normal OS install-time permission behavior still applies. Advanced static APK/IPA scanning remains available.

Optional model review uses a separate aggregate-metadata-only broker, not worker egress or executable model output. Server owner configures `MOBILEAG_LLM_ALLOWED_PROVIDERS`, exact model IDs/keys and loopback origins as documented in `.env.example`; each assessment must also explicitly approve metadata egress. Provider configuration is not a health check. See `docs/guided-assessment-2026-10-06/README.md` for stages, endpoint/provider matrices and validation boundaries.

Provider selection: Configuration → LLM provider configuration. Start Assessment keeps a read-only selection summary and explicit primary/secondary egress consent. All adapters can be selected to inspect setup; **Setup required** is not permission to execute. Configure the exact named variables privately on the server, restart and Refresh providers. Selection is retained on refresh; AI still requires a ready catalog and explicit metadata-egress consent. The assessment and advanced static modal link to this Configuration selector. Provider choices are session-only, retained during navigation, reset on reload and not saved by Save Settings. See `docs/provider-selector-2026-10-06/README.md` for the tested UI states; no live provider health is inferred.

## Shared interface and recovery

All ten views share local interface assets, per-view headings, keyboard navigation and a collapsible mobile menu. Upload is not execution. Triage confirmation requires explicit reproduction notes; cancel/empty notes send no mutation. API captured-response analysis needs an actual status and an authorized redacted capture, stays local, and produces unverified candidates, not a clean/security verdict. Settings readiness shows actual harmless local probe results. See `docs/interface-refresh-2026-10-06/README.md` for browser, accessibility, packaging and test evidence and remaining limits.

## Primary / secondary AI review

Guided assessment accepts a distinct optional secondary, with separate explicit metadata-egress consent. Both destinations must be server-configured/approved. The broker attempts secondary once only after actual primary HTTP 429, never for auth/timeout/content/other errors, and never loops. Each assessment starts with primary; revocation/cancellation stops continuation. Actual provider/model/attempt outcomes are recorded. This is not CLI-router fallback or increased provider quota. See `docs/provider-fallback-2026-10-06/README.md`. Never commit secrets in `.env.example`; keep keys private and preserve user changes.

See `docs/llm-configuration-2026-10-07/README.md` for the provider-control move, real browser checks and preserved authorization boundaries.

## Advanced workspace UX

Ctrl/Command K or Find a section opens navigation-only search; `/` does not interrupt editable fields. Contextual Next steps reports actual selected jobs, never confirmed vulnerability counts from static candidates. Compact/focus preferences are page-local. Provider cards use the existing catalog/change/consent gates; server-provided broker ceilings are not measured usage/billing/quota. See `docs/advanced-workspace-2026-10-07/README.md` for browser/packaging evidence and limits.

## Automatic local readiness

Start Assessment automatically checks the harmless host sandbox/tool configuration, host-only ADB inventory, saved scope and public provider catalog after authentication and before Start. It does not select/connect/boot devices, execute device shell, install dependencies, contact models or approve scope. Guided submission blocks unavailable static-worker prerequisites and non-online/unapproved DAST serials; production worker authorization/isolation remain independent.

Explicit device selection may automatically observe the process name via ordinary-shell `ps -A` ONLY with the saved exact `frida_status` action. This device-wide read-only observation is separate from `frida` attachment approval. Default badges are not checked; unknown inventory invalidates selection. Preset Preview generates text without instrumentation. Optional terminal-stage JSON download is opt-in for a newly explicitly started assessment, once only, not history replay. See `docs/auto-ready-2026-10-07/README.md`; tests remain synthetic, not live device/Frida or provider-health proof.

## Dashboard tools UI

The global Dashboard tools button exposes page-only session controls, navigation-only tour, and explicit bounded HTTP/curl self-reads. The workbench derives its destination from the listening socket, not client Host or a free-form URL. Never enter real mobile credentials in this panel. Findings/assessment views show evidence and coverage gaps; paired-account imports are synthetic operator evidence, not replay or independent proof. See `docs/dashboard-ui-2026-10-11/README.md` and the opt-in `tests/browser_dashboard_tools_ui.py`.
