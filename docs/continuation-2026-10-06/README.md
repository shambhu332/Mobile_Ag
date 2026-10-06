# Continued review: request/session and assessment suspension boundaries

Baseline: `1443063b7d2f69a10c436f5befa43fc08cbb2002`, MobileAg 0.1.0. Original working tree was clean. This follow-up contains the fixes, regression tests and preserved validation evidence. Prior artifacts/reports, uploads and `dist/` were not replaced. Environment and changed-source/fixture SHA-256 values: `validation/environment-source-hashes.json`.

## Confirmed and fixed

### 1. Request body suspension outlives session revocation

**Locations:** `mobileag/web/security.py:69-101,123-124`; `mobileag/web/app.py:1395,1413`; `mobileag/assessments/routes.py:13-15`; `mobileag/automation/routes.py:47-55,63-66` (current review locations).

**Root cause:** Middleware authenticated the header before awaiting request bodies and did not revalidate after reception. Assessment/automation routers then passed the *current server token*, rather than the request's authenticated credential, to background services. Rotation during body delivery could therefore authorize stale work under the replacement session.

**Prerequisites / reproduced impact:** A bearer valid when the request starts, plus an in-flight body completing after rotation/expiry. This is not an unauthenticated bypass or multitenant exploit. Synthetic ASGI requests through the actual application/rotation route reproduced stale scope mutation, assessment creation and invocation of mocked automation/DAST adapters. No device command was issued; the adapter invocation is not proof of device exploitation.

**Fix:** Capture the authenticated token in per-request state, bind service calls to it, recheck expiry/token before and after every awaited body receive, and return controlled 401/413 errors from the middleware-parsed DAST path. Valid current-token streamed JSON remains supported.

### 2. Assessment validation/hash suspension misses revocation/cancellation

**Locations:** `mobileag/assessments/service.py:38-40,58-65,80-92`.

**Root cause:** Session validity was checked only before asynchronous archive/hash validation. Scope/assessment state could be saved after token revocation. The pre-SAST hash similarly allowed cancellation/rotation to occur between guard and worker dispatch.

**Prerequisites / reproduced impact:** An already authorized create/run; rotation or cancellation during the controlled validation/hash suspension. The stale create wrote scope/history; cancellation/rotation during the pre-static hash still dispatched the mocked worker, although later checks stopped subsequent work. No live target operation was demonstrated for this case.

**Fix:** Revalidate session after archive/hash validation, revalidate environment ceilings before persistence, and guard immediately after run-time hashes before starting/continuing stages. Already issued operations cannot be undone, and hashing threads may finish after cancellation.

## Reproduction and validation

```bash
python -m pytest -q tests/test_session_boundary_regressions.py --disable-warnings
python -m pytest -q --disable-warnings
python scripts/verify-dashboard-assets.py
python tests/browser_product_regression.py --server-python "$(command -v python)" \
  --chromium /home/shambhu/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome \
  --axe assets/node_modules/axe-core/axe.min.js --output /private/new-browser-evidence
```

- Existing baseline suite: **212 passed**, before edits.
- Final new tests against a temporary archive of the exact baseline revision: **11 failed, 3 passed** (`validation/pre-fix-final-regressions.txt`). Temporary checkout removed. The same final tests against the fix: **14 passed** (`validation/post-fix-tests.txt`). Three original controls already passed; not every added test represents an original defect.
- Full suite after final edits: **226 passed** (`validation/full-tests.txt`). **11672 deprecation warnings**, primarily pytest-asyncio/Python 3.14, remain; not a warning-free validation.
- Local assets verified; `git diff --check` passed.
- Browser: real loopback auth/router/store/UI with synthetic SAST/navigation adapters; all ten tested views had zero automated axe violations, no page errors or outside-loopback runtime requests. Expected wrong-token 401 and blocked-inline-event CSP console messages are negative-control evidence, not silently omitted. See `validation/browser/` and `validation/browser-execution.txt`.
- Initial probe omitted JSON Content-Type and therefore produced three unrelated 422 responses; retained as `validation/initial-fixture-run.txt`. Corrected pre-fix evidence uses valid JSON and actual rotation, never weakened authorization. The original six-test run is separately retained in `validation/pre-fix-tests.txt`.

No commercial providers, target APIs, real devices or real decompilation were exercised in this follow-up. No new ordinary-app vulnerability, CVSS/bounty conclusion, production certification, wheel-build result or remote CI execution is claimed. Current unrooted owned-app acceptance, representative APK corpus/load, real inference, and manual accessibility gates remain open in the existing guided-assessment documentation.
