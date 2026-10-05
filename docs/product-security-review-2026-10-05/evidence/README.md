# Evidence and reproducibility

All fixtures are synthetic. `synthetic-review-only` is an intentionally fake token used solely on an isolated loopback test server; it is not a saved user credential and must not be used for a real deployment. No target APK/device/account was tested. Keep this baseline evidence separate from later remediation validation.

## Files
- `source-snapshot.json`: commit, host/Python and SHA256 source inventory.
- `routes.json`: AST-extracted37 explicit routes and20 request models, exact locations/parameters.
- `pytest.txt`: complete existing-suite outcome.
- `local_probe.py` / `local-results.json`: analyzer fixture, negative API controls, privacy prompt, persisted/unknown feedback and canned Copilot/agent metadata.
- `analysis_probe.py` / `analysis-results.json`: source-comment suppression, cross-scan iOS IDs, nested capture error, effective config, mock crawler and separately labeled out-of-root context helper lead.
- `synthetic-finding.json`: actual detector-produced crypto candidate used for UI injection test (fixed synthetic ID for reproducibility).
- `browser_probe.py` / `browser-results.json`: real page rendering, benign callback injection plus GET status, semantically audited DOM and eight-view geometry. Global marker is installed by test harness solely to record execution; application authorization stays unchanged.
- `desktop.png`, `narrow390.png`, `proof-without-runtime.png`: real Chromium screenshots, synthetic data only.
- `python-dependencies.json`: installed validation-environment versions, not a deployable lockfile.
- `dependency_probe.py` / `dependency-osv.json`: public name/version-only batch advisory lookup, date and coverage recorded.
- `secret-pattern-locations.json`: known secret-pattern locations only; no matched secret values preserved.

## Reproduction

Run from repository root using a project virtualenv with declared dependencies plus pytest. Browser script uses system Playwright and an explicitly selected cached browser; change only its executable path to your installed Chromium when replaying.

```bash
PYTHONPATH="$PWD" /path/to/project-venv/bin/python docs/product-security-review-2026-10-05/evidence/local_probe.py
PYTHONPATH="$PWD" /path/to/project-venv/bin/python docs/product-security-review-2026-10-05/evidence/analysis_probe.py
python -m pytest -q
```

`local_probe.py` creates a private temp directory, writes one persisted synthetic dashboard and a runner, and records path in `/tmp/mobileag-product-review-path`. Start that runner on an unused loopback port (probe uses18764):

```bash
R=$(cat /tmp/mobileag-product-review-path)
MOBILEAG_DATA_DIR="$R" MOBILEAG_API_TOKEN=synthetic-review-only OFFLINE=true \
MOBILEAG_ALLOWED_DEVICES='' MOBILEAG_ALLOWED_ORIGINS='' MOBILEAG_ALLOWED_CONNECT='' \
PYTHONPATH="$PWD" /path/to/project-venv/bin/python "$R/runner.py"
# Separate terminal:
python docs/product-security-review-2026-10-05/evidence/browser_probe.py
```

Stop only that temporary server afterward. It stubs graph availability and refuses device commands, deliberately producing an injected ADB500 in the screenshot. Do not mistake that error for a newly reproduced production ADB defect. Browser assets are fetched from the actual public CDN URLs; no remote application API is tested. The harmless injected marker calls only authenticated local `/api/status` and never exfiltrates data or commands a device.

The fixture is generated at decompiled-source/detector boundary then persisted using the existing dashboard schema. **It does not claim a complete built APK → decompiler → default filtering → dashboard exploit.** Add that separate end-to-end synthetic APK regression when implementing S01 remediation. The filter suppression probe uses standalone source with six references and offline settings; source comments may not survive APK decompilation.

The out-of-analysis-root context helper test is a lead only: caller control from an attacker route is unproven. All crawler/provider outputs are mocks, not live device/provider impact. No load/flooding, image CVE exploitation or ordinary-app mobile exploit testing was done.

Advisory lookup is optional and networked:
```bash
python docs/product-security-review-2026-10-05/evidence/dependency_probe.py
```
Only public package metadata is sent to OSV; do not send private dependency names without reviewing the package list. This captured list contained public packages excluding the local project.

## Final harness control
The initial callback setup was a function-valued `page.evaluate` expression that
Playwright invoked, producing an extra marker execution. It was corrected to an
explicit initializer function returning no value. The final recorded benign-copy
control is0 executions; the crafted-copy control is1 execution and local authenticated
GET200. Earlier count2 observations are superseded; this was a harness-counting artifact,
not an additional application exploit. No application authorization behavior was changed.
