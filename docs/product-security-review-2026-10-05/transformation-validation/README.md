# Validation boundaries and reproduction

Date: 2026-10-05. Source baseline before this pass: `e0af87a7967e2c4ff3fe77bc496d35dad8a66467`. The source hash ledger identifies the tested modifications; baseline audit evidence is preserved in its original folders. Package metadata remains 0.1.0, so use the source/wheel SHA-256, not the version string alone, to distinguish this build.

## Reproduce

1. Install the tested project environment using `requirements/validated-python314.txt` as constraints; this is a version snapshot, **not** a fully hashed cross-platform lock.
2. `python -m pytest -q` — device commands/provider adapters are mocked. Production has no test-mode sandbox bypass. Unit executor injection is explicit in `tests/conftest.py`; namespace and cgroup validation is independent below.
3. `PYTHONPATH=. python tests/sandbox_process_regression.py --output /tmp/mobileag-process-evidence` — actual ordinary-user bubblewrap/systemd scope; generated read-only archive and Mach-O header/ZIP fixtures only. It checks missing home/passwd, read-only input, no provider key, loopback-only namespace, actual aggregate resource properties, an unverified iOS candidate and a malformed APK's incomplete outcome. This is **not** a current ordinary-app exploit or a complete real APK/iOS corpus assessment.
4. Run `python tests/browser_product_regression.py --server-python /path/to/project/python --chromium /path/to/chromium --output /tmp/mobileag-browser-evidence --axe /path/to/axe-core/axe.min.js` using system Playwright and a local browser/test library. The library is test instrumentation, not shipped UI code or an authorization hook. Real app CSP stays enabled. The server uses synthetic source/findings, no real devices/models, and a local token that is not included in the result.
5. `npm ci --prefix assets --ignore-scripts && python scripts/build-dashboard-assets.py && python scripts/verify-dashboard-assets.py` — exact locked build/runtime dependencies, no CDN. Record `npm audit --omit=dev --json` separately from the full build dependency audit.
6. `python -m build --wheel` — install the wheel `--no-deps --target` into a fresh temporary directory, run outside the checkout with the tested dependency environment and normal loopback Host. Verify protected APIs, packaged local assets and actual readiness. Do not make `testserver` a production allowed Host to make a test pass.

## Evidence interpretation

- **155 tests passed** in the final run. Eight Chromium fixture views had zero reported axe violations; this is fixture coverage only.

- Full regression suite verifies real negative controls, not root/device authorization bypasses.
- Browser: actual SecretScanner → synthetic candidate → safe rendered copy → persisted triage. Eight fixture views, 320px/390px layout, no external runtime requests, marker execution count zero, self-only script CSP negative control. The **expected** CSP console error is the deliberately blocked inline-handler probe, not an application page error.
- Axe automated fixture results are not full WCAG, screen-reader or all-state certification.
- Actual user cgroup properties prove configured aggregate limits. No stress/fork-bomb or memory exhaustion tests were performed.
- Cold dashboard-import timing is a single host smoke measurement; cloud SDK absence was checked. No before/after throughput guarantee is inferred.
- Python advisory check covers the 108 pinned installed packages and found no reported advisories at assessment time. Runtime npm audit found zero reported advisories. Neither proves no vulnerabilities.
- Full npm build audit still reports the `braces`/`micromatch`/`@parcel/watcher` development chain. Runtime assets do not contain the watcher, the one-shot builder uses fixed researcher-controlled source patterns, and uploads cannot supply build globs. No deployed application exploit is demonstrated. This is a build-only investigation/hardening lead, not an inflated High finding. Upstream [braces advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) reported no patched version during assessment; maintain controlled build inputs and recheck before release.
- Vis was upgraded to 9.1.13 and its UUID peer pinned to 11.1.1 following the [UUID advisory](https://github.com/advisories/GHSA-w5hq-g745-h8pq). An advisory/package match alone was not treated as an exploitable graph attack.
- CSS is compiled using the documented [Tailwind CLI flow](https://tailwindcss.com/docs/installation/tailwind-cli); a later CLI dependency warning was reviewed instead of pretending “newest” means vulnerability-free.

## Artifacts

`tests.log`, `browser-results.json` and screenshots, `sandbox-results.json` and the generated synthetic IPA, `wheel-build.log`, `wheel-smoke.json`, `python-advisory-results.json`, `npm-runtime-audit.json`, `npm-build-audit.json`, `dashboard-import-smoke.json`, `current-openapi.json`, and `source-sha256.json`. No real API/session/provider/device credentials are included.

The saved artifact originals, backend versions, hashes and explicit limitations are authoritative. No authorized physical device or application account was supplied; no deployment, remote CI, production database, root hook or external API target was tested in this pass.
