# Product-review fix status — 2026-10-05

This is an **implementation update**, not a change to the historical review baseline `56d2febcb204e2a156d61677eac6197ea2543bd0`. The original findings, source snapshot and reproduction outputs remain preserved. The project owner subsequently requested publication of these fixes and evidence to GitHub. The exact published revision is recorded in Git history; validation snapshots retain their original pre-commit state.

## Preservation and scope

- The unfinished changes already present when this continuation began were preserved in `/tmp/mobileag-continue-backup-pkU7qg/source.tar` and `working-tree.patch` before additional editing. An earlier backup already exists at `/tmp/mobileag-before-review-fixes-s18tnvy5`.
- Existing uploaded applications, output reports, databases and user configuration were not used as test targets or deleted. Test servers used separate temporary data directories and synthetic session tokens; they were stopped afterward.
- Validation used synthetic Java/archive/findings, mocked ADB/Frida/Neo4j/providers, and researcher-controlled loopback servers. Public dashboard CDN assets may load. No real cloud model call or target API/device operation was performed.

## Implemented changes and evidence

| Review item | Current implementation | Validation / boundary |
|---|---|---|
| S01 finding-content JavaScript injection | Executable client code moved to packaged `web/static/dashboard.js` / `theme.js`; all inline event attributes removed. Static actions have registered callbacks; sample-derived values stay in closures behind opaque action IDs. Remaining reviewed fields are context-escaped. Response CSP excludes script `unsafe-inline` / `unsafe-eval`, with `nosniff`, frame denial, no-referrer and no-store headers. Only the root and two non-sensitive JS assets are anonymously readable. | Real Chromium: actual SecretScanner synthetic source → persisted finding → authenticated API → all four copy actions. Payload marker **0**, copied bytes match each original. Hostile finding-title HTML remains literal text. Deliberately injected inline handler is blocked by the actual response CSP. No CSP/auth bypass enabled. Compiled APK/decompiler integration is **not** established by this fixture. |
| S02 candidate-secret egress | SecretScanner retains a local redacted candidate without invoking an LLM. Router masks known formats for primary/fallback/consensus calls; provider initialization requires an explicit exact-name approval list. Offline is the default. The UI exposes effective policy, supported settings are durable, and each scan records the effective policy. | Mock transport tests for direct/fallback/consensus egress and no SecretScanner provider call; offline and unapproved-provider negative controls. Arbitrary unknown credential formats and proprietary non-secret source are **not guaranteed** to be masked. Deliberate approved cloud use still needs operator authorization. |
| S03 unsafe crawler/scope | UI hierarchy observation is package-bound and read-only; absent identity, other packages and system dialogs block the result. No automatic consent, text entry, taps or form submission. Frontend device selection is explicit and scope checked; no first-device fallback. Ordinary dashboard installs no longer auto-grant permissions. | Synthetic XML/mocked ADB negative controls and intended-package observation; Chromium shows no selected device. These tests are **not** real-device or ordinary-app exploit evidence. |
| S04 lost/cross-scan triage | `web/repository.py` implements SQLite metadata and transactional scan-scoped decisions, revision conflict detection, append-only analyst history and stale-worker protection. Existing dashboard JSON is imported without modifying the original. Running jobs reject triage. The legacy unscoped feedback endpoint returns 409 instead of guessing a scan. | New repository instance, duplicate rule IDs across scans, stale worker/revision, preserved original file, history and actual browser feedback POST/readback. Per-scan SARIF/API exports use current metadata; historical original files remain original snapshots, not rewritten reports. |
| S05 lexical suppression | Neighboring lexical sanitizer patterns do not establish sanitization. All detector candidates remain UNVERIFIED; below-threshold candidates carry review metadata instead of silently disappearing or becoming false positives. | Comment/no-comment and high-threshold controls retain the candidate. The scores and detectors remain heuristic, not inter-procedural proof. |
| S09 malformed nested capture | Typed, bounded capture transactions/header values/statuses/bodies replace unchecked dictionaries. | Wrong nested URL/header/status types return 422 rather than 500. |
| P01 broken dashboard boot | Missing optional element guarded; counts use actual loaded findings, absent metrics state Not assessed/Not measured. Optional graph/chart/icons no longer gate core finding rendering. Public source assets are packaged. Narrow layout is allowed to stack/scroll. | Chromium no page errors; real count 1 instead of hardcoded 21; all eight views rendered/visible in the smoke; 390px viewport reports document width 390. Not a complete accessibility or mobile interaction audit. |
| P02 fabricated execution/evidence | Proof pane uses analyst notes or an explicit no-runtime-evidence state. Local evidence-summary endpoint requires a real scan and makes no observed-exploit claims. Agent metadata is capability-only with unmeasured counts/times; individual run controls are disabled. Full scan action opens the real scan form. API badges/results use unverified/not-assessed wording; default response panes are sample previews, not observed replies. Generic reproduction guidance no longer declares success/impact. | Chromium proof negative control, capability views, real scan context/feedback; no invented target/demo endpoints. The local summary endpoint is **not** a conversational cloud Copilot. |
| Additional provenance/storage | Original upload bytes are SHA256-recorded, new uploads/snapshots/SQLite metadata use owner-only files, scan summaries are bounded/paginated, supported settings persist, CLI web binding is loopback-only. | Synthetic upload hash/immutability, permissions, summary and installed-wheel tests. Existing storage permissions are not silently rewritten; original decompilation artifacts still need appropriate operator storage protection. |

## Precise implementation review locations

- `mobileag/web/static/dashboard.js`: `bindAction`, delegated listeners, `renderDashboard`, `inspectFinding`, `getOrGenerateProofEvidence`, `submitTriage`, `selectDastDevice`, `loadPrivacyPolicy`.
- `mobileag/web/security.py`: `SecurityMiddleware.__call__` response headers and narrowly public JS resources.
- `mobileag/web/app.py`: `repository_import_legacy`, `effective_runtime_settings`, scan-scoped feedback/decision endpoints, typed `CapturedTransaction`, `live_scan_telemetry_worker` and `trigger_scan`.
- `mobileag/web/repository.py`: `private_write`, `ScanRepository.save`, `.triage`, `.history`, `.save_settings`.
- `mobileag/analysis/secret_scanner.py`: local candidate branch in `SecretScanner.scan`; `mobileag/llm/router.py`: `_init_providers`, `route`, `route_to_multiple`.
- `mobileag/dast/ui_crawler.py`: `parse_ui_elements`, `crawl_app`; `mobileag/filters/sanitizer_check.py`: `_get_code_context`, `_pattern_check`; `mobileag/filters/pipeline.py`: candidate retention branch.
- `tests/test_product_fix_regressions.py` and opt-in `tests/browser_product_regression.py` contain the new controls. Original negative controls remain enforced; tests expecting old fabricated behavior now require the corrected fail-closed behavior.

## Fresh validation

- Full suite: **141 passed, 1 third-party deprecation warning** (Python 3.14.7; publication recheck 94.88s). Existing and new tests are in `fix-validation/pytest.txt`.
- Actual Chromium **155.0.8059.12** smoke passes. `fix-validation/browser-results.json` contains copy/XSS/CSP/feedback/view controls and desktop/narrow screenshots. The sole recorded console error is the intentionally blocked inline-handler negative control.
- Python compilation, both client JavaScript syntax checks, and `git diff --check` pass.
- Wheel build and out-of-checkout installed-wheel checks pass: public dashboard/JS 200, anonymous settings 401, authenticated settings 200, safe offline default and CLI help. The app import is verified to come from the installed wheel target, not the checkout.
- Host: Linux `7.2.8-2-cachyos`; no target Android/iOS OS build exists because no real device/app was assessed. `source-hashes.json` preserves the pre-publication source snapshot; `publication-validation.json` records final source/wheel SHA256 values after whitespace-only JS normalization and a repeated full test/browser/wheel check; uploaded synthetic bytes are covered by the scan hash regression.
- During harness development, returning a marker function from `page.evaluate` caused Playwright itself to invoke it; the final setup uses an explicit block and asserts marker=0 before interaction. Playwright's string-based `wait_for_function` also conflicted with strict CSP; the final harness polls using DevTools evaluation **without** disabling CSP or changing authorization. These harness failures are not reported as application exploits.

### Reproduce

```bash
python -m pytest -q
node --check mobileag/web/static/dashboard.js
node --check mobileag/web/static/theme.js
python tests/browser_product_regression.py \
  --server-python /path/to/project/venv/bin/python \
  --chromium /path/to/installed/chromium
```

The browser helper creates its own fixture/server, refuses real device commands, and terminates its server on exit. Playwright is optional test tooling, not a runtime dependency.

## Still open / not claimed fixed

- **S06:** third-party CDN scripts still hold full page trust and remain unpinned/unbundled. CSP narrows script sources but does not make CDN compromise safe; bundle/pin/audit these assets before a hostile-sample production release.
- **S07:** native parsers/decompilers and analysis jobs still need hardened OS/process isolation, comprehensive budgets, cancellable workers and restart recovery. Thread timeouts are not a killable security sandbox; SQLite metadata is not a durable job engine.
- **S08:** no comprehensive retention/deletion/export policy or arbitrary-secret proof exists. Original raw artifacts and old files still require appropriate local protection. There is no claim that all secrets, git history or legacy files were sanitized.
- **S10:** local trusted single-operator only. No shared-user RBAC, tenant isolation, remote identity/session lifecycle, TLS termination or hardened remote deployment is implemented. The CLI's loopback restriction is not protection against someone manually deploying the ASGI app differently.
- Broader UX/accessibility, performance/load, integration/provider behavior and full production APK/decompiler output need further verification. A dashboard smoke is not a comprehensive production acceptance test.
- No current unrooted ordinary-app Android exploit, root-based privilege claim, numeric vulnerability score, bounty eligibility or blanket production-readiness claim is made.
