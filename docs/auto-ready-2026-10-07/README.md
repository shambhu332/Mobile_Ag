# Automatic readiness and approved orchestration — 2026-10-07

MobileAg **0.1.0**, baseline `afc58418e369422b25121da9a7674420ee3a58fb`. This update reduces setup/status/report clicks without introducing implicit target selection, cloud egress or dangerous device actions. Original artifacts and earlier evidence remain unchanged. User credential edits to `.env.example` and the private `.env` are excluded from all commits, package builds and evidence.

## What now happens automatically

1. After authenticating, **Start Assessment → Automatic readiness checklist** inspects the harmless local sandbox probe, trusted worker tool presence, host ADB availability/inventory, saved scope and public provider configuration. Provider selectors load without visiting Configuration first. Reconnect invalidates old readiness; Recheck retries explicitly.
2. Before Start, a fresh preflight blocks guided submission when offline-worker prerequisites are missing or the explicitly entered DAST serial is not online and server-approved. Device suggestions do not select a serial. Missing tools are explained, not installed. Actual server policy and isolated worker enforcement remain independent of these client-side usability checks.
3. After the user explicitly chooses exact scope/stages and approves Start, the **existing** guided service orchestrates offline SAST → approved observed read-only API cases → approved dedicated-device mapping → separately consented aggregate-only AI. This patch integrates readiness into that flow; it does not invent a second unrestricted scanner.
4. After **explicit online device selection**, process observation runs automatically only with saved exact-device **`frida_status`** approval. It uses bounded ordinary-shell `ps -A`; it never starts a server, calls `su`, attaches instrumentation or executes presets. Check Status can retry the same observation manually. Saved `frida` attachment permission alone does **not** approve this new action.
5. An optional unchecked-by-default checkbox downloads evidence JSON **once** when a newly explicitly started run finishes or pauses. Awaiting exact navigation review is a pause, not a completed exhaustive scan. History loading does not opt in. Manual Export remains available.

Readiness itself consumes **zero LLM requests/tokens**. AI stays optional; commercial token usage/billing/TPM remain unmetered. Configuration is not provider health. Host `adb devices -l` may start the local ADB daemon as normal ADB behavior, but does not connect/boot/select a target, run device shell or probe root. Inventory is capped at 100 rows, 64KiB and a three-second command timeout.

## Fixed misleading or miswired Device Diagnostics behavior

- Default ADB/Frida status is **not checked**, not hardcoded Ready. Executable availability is distinct from device connectivity/approval. Failed inventory reports unknown and clears stale selection/control state. Offline/unapproved rows are not selectable. No root/Android-build probe runs during inventory; unknown is not an assertion that a device is unrooted.
- Previously, **Check Status** posted an unpinning payload against `com.android.systemui`. It now uses a separate authenticated, exact-device/action-scoped process-observation route. The response explicitly says attachment and compatibility are not verified, even when a process name is observed. A renamed/hidden daemon may not be observed; this is not an exhaustive Frida health test.
- Previously, **Preview** also used the execution route. Preview now generates text only through an authenticated allowlisted generator route and requires no device. The preview region is keyboard-scrollable.
- Device operations are disabled until explicit online server-approved selection. The backend still independently checks saved action/package/device policy; enabled UI buttons are not authorization. Initialization controls accurately describe transient preset initialization/detachment, not persistent hooks.
- APK installation labels/toasts no longer claim forced runtime grants (`-g`); the existing request uses `grant_permissions:false`. Logcat starts uncollected, not “connected.” Empty diagnostic evidence is not a security verdict or a promise that fuzzing will find vulnerabilities.
- The 1Password announcement is outside this app's automation; this patch does not disable or manipulate browser extensions.

## Review locations and routes

| Location | Purpose / authorization |
|---|---|
| `mobileag/dast/adb_manager.py::discover_devices` | Host inventory only; never device-shell/detail/root probes |
| `mobileag/web/app.py::get_preflight`, GET `/api/preflight` | Current bearer session; harmless readiness plus public catalog/scope; no jobs, scope writes or model calls |
| `app.py::get_dast_devices`, GET `/api/dast/devices` | Session rechecked before inventory and after awaited work; configuration approval does not imply policy/action approval |
| `app.py::get_frida_status`, GET `/api/dast/frida/status?serial=...` | Exact environment ceiling AND saved `frida_status`; session/scope rechecked before/after bounded command; sanitized status only |
| `app.py::preview_frida_preset`, GET `/api/frida/presets/{script_type}` | Authenticated allowlist `crypto`, `root_bypass`, `unpinning`; generation only |
| `mobileag/web/policy.py`, `security.py` | Distinct read-only action and middleware mapping; no new device-scope exemptions |
| `web/static/auto-ready.js`, `session-actions.js`, `dashboard.js` | One coalesced check at connection; generation-based invalidation; no duplicate startup device probe; optional authorized observation after selection |
| `web/static/assessment.js` | Fresh preflight before explicit POST; existing consent/policy flow; one opt-in evidence download |
| `web/static/dast.js`, templates and interface CSS | Truthful status, safe GET status/preview, keyboard fleet controls, disabled-selection and error recovery |
| `tests/test_auto_ready.py` | 21 synthetic regression cases: no shell during discovery, bounds, unknown failures, authentication, exact action, before/after revocation, no attach/preview execution |
| `tests/browser_product_regression.py`, `scripts/wheel-smoke.py` | Real local router/auth/storage/browser flow with synthetic transports and packaged asset checks |

## Validation

- Full unit suite: **304 passed**, dependency deprecation/resource warnings retained in the log. No authorization negative controls were weakened.
- Desktop and 320px mobile Chromium: all ten views, **zero automated axe violations**, no page errors, no outside-loopback runtime requests. Verified local startup without selection/start, correct checklist placement, fresh blocked preflight preventing submission, inventory failure clearing selection, automatic process observation only after selection AND saved action, scope replacement blocking observation, preview/status with zero instrumentation POSTs, and only the opted-in assessment downloading once.
- Temporary installed wheel outside source checkout: **20 local scripts, 4 stylesheets**, protected unauthenticated APIs rejected. No dependency downloads; temporary package/install removed; original `dist/` preserved.
- Local asset/module-order checks, shipped JavaScript syntax, whitespace and staged credential scans passed. Relevant source SHA-256 and OS/Python/dependency versions are recorded in `validation/`. Desktop checklist and mobile screenshots visually inspected.
- Focused backend and UI snapshots are separately exported from the Git index, excluding private environment files, tested, committed and pushed in order. Publication details are recorded below after verification; no force push/reset/stash or credential staging.

## Boundaries / setup still required

You must configure host dependencies/server allowlists and exact private provider models/keys, boot your dedicated approved device, upload your owned APK, choose exact scope and approve execution. Automatic readiness does **not** install dependencies, provision/boot/connect/root devices, accept password-manager prompts, grant runtime permissions, bypass TLS/root detection, fuzz all components, replay write APIs, approve navigation input, resume interrupted work or upload raw APK/source/findings to models.

All dynamic/model fixtures are synthetic. No real APK/device/account/model was tested, so no current device OS/ABI/Frida compatibility, actual APK analysis coverage, provider entitlement/health/quota, cloud billing, ordinary-app exploitability or production readiness is claimed. Root/shell observations and hooks are not ordinary-app exploitation proof. The browser's worker-readiness result is mocked, not evidence that this user's current host sandbox/tools are functional. The production harmless probe is reused unchanged and reports actual readiness when the user connects. Local package/axe checks are not remote CI/deployment or full accessibility certification.

## Reproduce safely

```bash
python -m pytest -q
python scripts/verify-dashboard-assets.py
for file in mobileag/web/static/*.js; do node --check "$file"; done
python tests/browser_product_regression.py --server-python /usr/bin/python \
  --axe assets/node_modules/axe-core/axe.min.js \
  --output /tmp/mobileag-auto-ready-browser-check
```

Keep private keys in a private server environment, never `.env.example` or evidence. Rotate keys previously exposed in chat. Exact target authorization is still mandatory; this update does not authorize unrelated devices or applications.

## Sequential publication

1. [`5baa239`](https://github.com/shambhu332/Mobile_Ag/commit/5baa239f3a3fdd0d6242326917cfaf1d0d445911): host-only discovery, authenticated preflight, distinct scoped process observation, generation-only previews and 21 boundary regressions. Exported staged tree: **304 tests passed**, local assets/JS/credentials checked. Pushed and GitHub main SHA verified.
2. [`56f7577`](https://github.com/shambhu332/Mobile_Ag/commit/56f757771364137dc40b4376a3473c044653512c): automatic checklist/start gates, opt-in evidence download, truthful/disabled device UI and browser/package regression updates. Final exported staged tree: **304 tests passed**, full desktop/mobile browser acceptance, assets/JS/credentials checked. Pushed and GitHub main SHA verified.
3. This documentation/runbook/evidence bundle is a separate final commit; its SHA is recorded by Git history. `SHA256SUMS` covers this bundle; `validation/source-sha256.json` covers the tested implementation. Private credential edits remain uncommitted by design.

Browser and staged validation use temporary checkouts without private environment files; those were removed. Real devices, model providers and external runtime resources were never contacted during validation. Existing dependency warnings are preserved; screenshots contain synthetic fixture state only.
