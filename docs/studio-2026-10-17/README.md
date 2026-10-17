> Historical initial UI snapshot. See the [subsequent workflow expansion](../studio-parity-2026-10-17/README.md) for current feature coverage and separate validation.

# MobileAg Studio — implementation and validation

## Open the interface

With `MOBILEAG_API_TOKEN` configured privately:

```bash
mobileag web --ui --host 127.0.0.1 --port 8080
```

Open the printed `/ui` URL (normally `http://127.0.0.1:8080/ui`), select **Connect workspace**, and enter the same token. Port conflicts may cause the existing launcher to choose another port. Without `--ui`, existing API-only behavior remains unchanged. This task did not leave a server running or publish anything remotely.

The UI implements static assessment staging/start, scan history/search/pagination, finding/source-context inspection, coverage/provenance, SARIF export, read-only scope and explicit readiness inspection. Advanced live workflows remain API/CLI-only. See [the architecture review and design](REVIEW.md) for reviewed code locations, design decisions and remaining gaps.

## Screenshots

Screenshots of populated views contain **synthetic regression records, not actual security findings**. No fixture data is shipped with the application.

- [Desktop, disconnected](validation/overview-disconnected.png)
- [Desktop, populated synthetic workspace](validation/overview-synthetic.png)
- [Finding and evidence inspector](validation/finding-synthetic.png)
- [390px mobile](validation/mobile-390.png)
- [320px mobile](validation/mobile-320.png)

## Verified results

| Check | Result / boundary |
| --- | --- |
| Full pytest suite | **1,372 passed** in 52.83 seconds; [terminal log](validation/pytest.txt). Unit tests use the repository's isolated/mocked device boundaries. |
| Real Chromium browser | Passed at 1440px desktop and 390px/320px mobile; [results](validation/results.json). |
| Automated accessibility | axe-core WCAG 2 A/AA and WCAG 2.1 AA checks: zero violations across six checked states (disconnected, overview, evidence dialog, upload dialog, mobile 390/320). Not a complete accessibility certification or manual screen-reader audit. |
| Browser execution/privacy | Zero page errors and zero external requests. Real local bearer validation, database reads, upload staging and SARIF download. |
| Submission controls | Invalid extension rejected locally; upload does not start a scan; consent required; safe static-only request tested. Both blocked (409) and accepted (200) scan submissions are intercepted synthetic responses, **not real engine runs**. |
| Authentication boundaries | Exact public asset allowlist; API/upload auth remains required; hostile host/origin rejected; expiration fails closed; repeated enable is idempotent; API-only default preserved. |
| Secret/rendering hygiene | No browser persistence; input cleared; disconnect clears rendered evidence; markup in findings stays text. Unit/source checks cover session/selection generation guards, but exhaustive concurrent browser race testing remains future work. |
| Packaging | Final wheel built and installed in a temporary directory, imported from outside checkout; all four UI paths serve; unauthenticated API remains denied; SARIF schema ships. [Result](validation/wheel-smoke.json). |
| Syntax / whitespace | `node --check`, Python compilation and `git diff --check` passed. |
| Preservation | All 93 previously deleted paths remain deleted. No reset, checkout, commit, push or restored legacy bundle. |

### Tooling and baseline limitations

Host Python was 3.14.8. Initial system-Python pytest collection stopped because declared dependency `packageurl` was absent. A temporary `/tmp/mobileag-studio-venv` with system site packages was created, with declared `packageurl-python==0.17.6` and `openapi-spec-validator==0.9.0`; no global packages or project dependency versions were changed. The final full suite used that environment with dotenv disabled and warnings suppressed. The original missing-dependency baseline was not a code regression.

The default Playwright browser binary was absent; the installed Chromium 155.0.8059.12 executable at `~/.cache/ms-playwright/chromium-1247/chrome-linux64/chrome` was verified and used explicitly. The browser script's original string-based wait was incompatible with the application's no-unsafe-eval CSP; it was replaced by a locator visibility wait without weakening CSP. Final results supersede those preliminary attempts.

axe-core 4.14.0 was installed only under `/tmp/mobileag-studio-a11y`; it is test tooling, not a runtime dependency or shipped asset. [Provenance](validation/provenance.json) records package/browser-host context, UI hashes and the final wheel hash. No real APK, Android OS build or device exploit evidence exists for this UI task.

## Reproduce checks

```bash
# In a test environment with the project's declared dependencies installed:
python -m pytest -q -W ignore
node --check mobileag/studio/assets/app.js
python tests/browser_studio.py --output /tmp/mobileag-studio-browser
# Optional accessibility checks with a locally installed axe-core file:
python tests/browser_studio.py --output /tmp/mobileag-studio-browser \
  --axe /path/to/axe-core/axe.min.js
```

The browser script creates a temporary data directory and server, seeds synthetic records, stages a synthetic archive, intercepts scan-execution requests, and stops its server afterward. The result file starts as `incomplete` on every invocation so a failed rerun cannot retain a previous pass claim.

## Changed integration points

- New `mobileag/studio/__init__.py` and three offline assets.
- `mobileag/cli.py` / `web/app.py`: explicit `--ui` startup.
- `mobileag/web/security.py`: exact optional public-shell paths; no general API exemption.
- `pyproject.toml`: ship new assets in wheels.
- `scripts/wheel-smoke.py`: preserve API-only checks and additionally validate opt-in shell from installed wheel.
- New unit/browser tests, docs and reference screenshots. Existing README/architecture documentation updated without restoring legacy UI.
