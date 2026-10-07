# Advanced dashboard workspace — 2026-10-07

MobileAg 0.1.0; baseline `ad0cd277a4128955ec5818377665615a4e754eca`. Validation was recorded before publication; Git history records the focused commits and their publication status. Original artifacts, earlier validation bundles, `dist/` and private environment files are preserved. The pre-existing credential-bearing user edit to `.env.example` is excluded from this implementation and evidence.

## Implemented UI/UX

### All ten workspace views

- Searchable **section command palette**: Ctrl/Command K, or `/` outside editable fields. Search workflow keywords such as manifest, findings, history, provider, scope or APK. Arrow Down moves to results; Arrow Up/Down/Home/End move between results; Enter navigates. Native modal focus trapping, explicit Close and Escape restore focus. Empty queries/results are handled with text-only rendering. Navigation does not execute scans, replay, models or device input.
- **Comfortable/compact density** reduces content spacing without shrinking minimum 44px interactive controls. **Desktop focus layout** hides the sidebar while leaving command navigation and the layout toggle available. Neither layout changes authorization or job state. Layout preferences stay in memory for this page only.
- **Contextual Next steps** guide per view: actionable navigation to relevant review/configuration screens, scope/evidence cautions and the actual selected job/status/recorded candidate count. No job means no implied results. It never labels static candidates as confirmed exploits or silently executes a suggested step.

### LLM Configuration

- Searchable provider/model cards, with All / Configured / Setup required / Local / Cloud filters.
- Exact configured models, cloud/loopback classification, missing server setup reasons and selected primary/secondary badges. “Configured” is explicitly not connectivity, entitlement, quota or health.
- **Set primary / Set secondary** card actions reuse the original selectors/change handlers, clearing relevant consent. Selecting unavailable adapters remains useful for setup inspection but cannot execute. Duplicate secondary choices are disabled in card actions and independently rejected by the backend.
- **Primary/secondary comparison and approval checklist** separate catalog loading, server configuration and per-assessment egress consent. No credentials editor, automatic model probe, implicit fallback selection or key storage.
- **Broker limits** are supplied by the authenticated catalog from the same constants that enforce transport/request/output bounds. At most one primary plus one separately approved secondary on real HTTP 429; requested output ceiling 1,024 tokens/attempt; request timeout 25s and HTTP transport timeout 15s. These are request ceilings, **not** consumed tokens, billing, tokens/minute, account quotas or scan-time estimates. Actual usage remains unmetered.

Provider/backend authorization semantics are unchanged: aggregate-only review, keys/models/approved destinations private on the server, static worker always offline, separate explicit primary/secondary consent, real HTTP 429 only, no retry/tertiary loops, and cancellation/revocation checks. Starting assessments, scope writes, replay, device actions and session changes retain their original explicit routes/approvals. See [fallback boundaries](../provider-fallback-2026-10-06/README.md).

## Review locations

- `mobileag/web/static/experience.js`, `experience.css`: shared navigation, keyboard/modal recovery, layouts, contextual guide and provider explorer. No fetches or target-operation calls; render user/server text with `textContent`, never HTML interpolation.
- `mobileag/web/static/assessment.js`: publishes public catalog/selection/consent snapshots, preserving existing submit/catalog guards and secret-free controls.
- `mobileag/llm/broker.py`: public limits from existing enforced constants; provider protocols and authorization unchanged.
- `mobileag/web/templates/index.html`: ordered local assets; no remote runtime assets or inline scripts introduced.
- `tests/browser_product_regression.py`, `tests/test_interface_contracts.py`, `tests/test_guided_assessments.py`: navigation/placement/limits/negative controls and real loopback router/storage.
- `scripts/wheel-smoke.py`: shipped scripts/styles and protected endpoint checks in an installed wheel outside checkout.

## Verified results

- **283 tests passed** (13,783 dependency deprecation/resource warnings). Existing broker authorization, cancellation, HTTP 429 fallback and malformed-content negative controls retained.
- Real Chromium/loopback acceptance: keyboard section search, arrow/Enter navigation, no mutations from search/layout/guide, native modal focus/escape recovery, editable-field slash safety, compact/focus layout, actual/empty selected-job guidance, provider filters and card selection clearing consent, stale-catalog failure blocking and synthetic primary 429 → secondary 200.
- All ten views: zero automated axe violations on desktop and 320px mobile; no page errors, no outside-loopback runtime requests and every mobile document width 320px. Command dialog also passed axe and size/usability checks on mobile.
- Temporary installed-wheel smoke outside checkout served **19 local scripts and 4 stylesheets**, including the new assets, and denied protected unauthenticated APIs. No dependency downloads; temporary package/install cleaned and original `dist/` untouched.
- Local pinned asset/module order, all shipped JavaScript syntax and diff whitespace checks passed. Desktop provider/workspace and mobile palette screenshots visually inspected. Layout settings are not persisted; actual commercial usage/cost/quota are not measured.

## Sequential publication checks

The implementation was committed and pushed in dependency order, with each push verified against the GitHub `main` SHA:

1. [`fd1332d`](https://github.com/shambhu332/Mobile_Ag/commit/fd1332d8d21950a45878f50f3ab9231770da49c5): enforced broker limits and test; staged snapshot **280 tests passed**.
2. [`8c2b55c`](https://github.com/shambhu332/Mobile_Ag/commit/8c2b55cf0e179c42bfda9b4efc7b96d337f9998e): navigation, guidance, layouts and their tests/package smoke; staged snapshot **283 tests passed** plus independent desktop/mobile browser acceptance.
3. [`a001345`](https://github.com/shambhu332/Mobile_Ag/commit/a00134523856fd3b2a4f4539e13fe9db44283725): provider explorer, consent checklist, snapshot wiring and tests; staged snapshot **283 tests passed**. Complete committed implementation hashes match the final browser/package evidence above.

Each snapshot was exported from the Git index into a temporary checkout (private environment files excluded), checked for credentials/whitespace, tested with synthetic fixtures, and checked for local assets and JS syntax. Temporary checkouts were removed without overwriting the final working files or the user's `.env.example`. Supplemental logs are in `validation/publication-checks/`; dependency warnings remain. This documentation/evidence bundle is a separate final commit; Git history records its SHA. Original validation manifests describe the earlier pre-publication state, not a live deployment.

## Validation and limitations

Final results and source/environment hashes are in `validation/`; `SHA256SUMS` identifies this bundle. Browser acceptance uses synthetic keys, redacted synthetic fixtures, mocked commercial/device adapters and researcher-controlled loopback application routes/storage. Axe is injected by trusted Playwright instrumentation, not by relaxing application CSP; the arbitrary inline-handler negative control remains. Desktop screenshots were visually inspected. Automated axe checks are not full accessibility certification.

No real APK/device/account/model was contacted. No cloud health/entitlement, billing/TPM accuracy, exploitability, remote CI or production readiness is claimed. This is a UI/UX enhancement, not a new autonomous exploitation engine. Dependency deprecation/resource warnings remain. Local package smoke does not establish deployment readiness.

Reproduce:

```bash
python -m pytest -q
python scripts/verify-dashboard-assets.py
node --check mobileag/web/static/experience.js
node --check mobileag/web/static/assessment.js
python tests/browser_product_regression.py --server-python /usr/bin/python \
  --axe assets/node_modules/axe-core/axe.min.js \
  --output /tmp/mobileag-advanced-browser-check
```
