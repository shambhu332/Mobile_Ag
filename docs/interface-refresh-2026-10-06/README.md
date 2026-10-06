# Workspace UI/UX refresh — 2026-10-06

MobileAg 0.1.0; baseline `ef1a154b7ce56e3cec0ebb33d67efffed735c7dd`. This refresh includes the earlier local provider-selector fix. Validation was recorded before commit/push; publication status is tracked by Git history. Original APKs, prior evidence and `dist/` artifacts remain untouched. Source hashes and environment details identify the tested working tree, not a new release or deployment.

## Updated areas

| Area | Changes / review locations |
| --- | --- |
| Shared workspace | Local design tokens, spacing, focus rings, contextual headings, one current-navigation indicator, responsive cards/drawers and a collapsible mobile menu. `interface.css`, `interface.js`, `index.html`, `workspace.js`. Old graph instances are destroyed on scan changes. |
| Start Assessment | Four labelled fieldsets, stage progress, selected-plan summary, busy upload state, explicit missing-artifact checks and collapsible technical evidence. Upload never starts testing. `assessment.js`. |
| Optional AI | All ten existing adapters selectable to inspect setup, exact public configuration names, read-only configured model and retained refresh selection. Missing approval/configuration/catalog/consent still blocks execution. `assessment.js`, `llm/broker.py`. No dedicated Qwen/DashScope adapter added; configuration is not connectivity or entitlement. |
| Attack Surface | Selected-scan summary, bounded responsive graph/KPI panels and honest candidate/coverage labels, not certification. `workspace.js`, `interface.css`, `index.html`. |
| Findings & Evidence | Medium/Low/Info filters, file-path search, keyboard candidate cards and a labelled native reproduction-notes dialog. Empty/cancelled confirmation sends no mutation; backend validation still authoritative. `findings.js`, `interface.js`. |
| Scan History | Busy/empty/error states, actionable retry, useful load failures, table caption and bounded mobile table scrolling. `history-settings.js`. |
| Analyzer Capabilities | Informative capability markers rather than unusable execution controls; missing runtime/counts remain unmeasured. `history-settings.js`, `index.html`. |
| Configuration | Actual provider-selector link, load/save feedback and duplicate-save latch; readiness rendered as explicit local probe cards plus raw details. Changing retention scan selection invalidates its deletion preview. `history-settings.js`, `workflow.js`, `interface.js`. |
| Device Diagnostics | Explicitly scoped diagnostic language; removed misleading automatic root/TLS/dynamic toggles from the offline static modal. Device-wide prerequisites and server restrictions remain enforced. `index.html`, `uploads-exports.js`. |
| Taint Dataflow | Empty/no-result state is not assessed, not "clean". Confidence resets to not measured instead of retaining stale values. `taint.js`, `index.html`. |
| API Review | No fake successful responses, mock credentials/admin request body or "secure gateway" claim. Invalid header JSON blocks replay. Captured-response analysis requires an actual 100–599 status plus explicit owned/redacted capture confirmation; local analyzer candidates remain unverified. Bulk action opens scoped planning, not fictitious response tests. `api.js`, `index.html`. |
| Navigation Review | Shared responsive scope/approval form styling; existing exact-control approval/service boundaries preserved. `interface.css`. |
| Export / local summary | Export dropdown opens, Escape restores focus, export disabled without a scan. Summary drawer is labelled local-only, hidden content removed from accessibility/layout, and errors/loading state explicit. It is not an AI chat or runtime verifier. `dashboard.js`, `uploads-exports.js`, `copilot.js`, `interface.js`. |

JavaScript locations above are under `mobileag/web/static/`; template is `mobileag/web/templates/index.html`. No remote UI dependencies were introduced.

## Final validation

- **246 unit tests passed**, including 11 provider-catalog/setup/privacy/approval tests and 9 interface contract tests. Deprecation/resource warnings remain; this is not a warning-free run. See `validation/full-tests.txt`.
- Actual cached Chromium on a temporary loopback server: all ten views, current-navigation/heading state, JSON export, keyboard finding selection, file-path filtering, cancel/empty triage no-mutation controls, history 503/retry recovery, captured-response guards, provider ready/setup/catalog-failure gates, guided assessment and exact navigation approval. Authentication, routing and persistence remain real; device/static-executor/model transport adapters use synthetic fixtures.
- Zero axe violations in all ten tested desktop and 320px mobile view states (WCAG 2 A/AA and 2.1 AA rule tags), no page exceptions and no outside-loopback browser/runtime requests. Intentional wrong-token/CSP/simulated-outage diagnostics remain recorded. This is **not full WCAG, production or complete interaction certification**.
- All ten views fit a 320px document without page-level horizontal overflow. Mobile navigation opens for selection then collapses; the current heading remains within the first 500px. Wide tables/code have their own scrolling.
- Temporary wheel built without dependency downloads, installed outside checkout, imported from its installed location, served all **18 local scripts** and included the interface stylesheet; protected APIs denied unauthenticated calls. Temporary build/install cleaned up; original `dist/` unchanged. See `validation/wheel-smoke.txt` and its wheel hash.
- JS syntax, pinned local asset verification and `git diff --check` passed. Browser screenshots/results, source hashes and evidence checksums accompany this report.

Development failures are preserved separately: initially collapsed evidence was opened before reading; capture assertions now accept actual unverified candidates instead of assuming zero; an actual contrast defect was corrected in the palette; native-dialog close tests wait for DOM cleanup. The new mobile menu fixture now explicitly opens navigation (and restores desktop size for desktop checks); mobile axe exposed a taint-results scrolling region, now labelled and keyboard-focusable. Negative safety controls were not removed to make tests pass.

### Reproduce in the development environment

```bash
python -m pytest -q
python scripts/verify-dashboard-assets.py
for file in mobileag/web/static/*.js; do node --check "$file" || exit; done
python tests/browser_product_regression.py --server-python /usr/bin/python \
  --axe assets/node_modules/axe-core/axe.min.js \
  --output /tmp/mobileag-ui-browser-check
```

Browser acceptance requires installed Playwright and the cached Chromium path (override with `--chromium`); axe is local development tooling. The harness creates/deletes its temporary server/data. It does not contact a real device, target API or commercial model.

## Use / remaining limits

Restart the server from this checkout, then reload the dashboard:

```bash
python -m mobileag.cli web --host 127.0.0.1 --port 8080
```

A separately installed application needs the changed wheel rebuilt/reinstalled before restart. No existing unrelated service was restarted. Credentials remain private server configuration; the UI does not enable unapproved providers or persist keys. See [provider setup instructions](../provider-selector-2026-10-06/README.md).

No real APK/decompiler/device/target API/provider inference, fresh authorized account entitlement, production deployment, remote CI or ordinary-app exploit proof is claimed. No new provider integrations or security findings are asserted. Offline parsing, aggregate-only model input, explicit scope/consent and backend authorization remain the boundaries.
