# MobileAg engineering and security review

Date: 2026-10-05. Scope: current local working tree, not just committed HEAD.

## Bottom line

The application has reproducible security-boundary failures and significant analysis-integrity defects. Passing unit tests does not establish that scans are real, complete, correctly filtered, or that runtime hooks executed. Keep the dashboard local and do not use its CONFIRMED labels as proof of exploitable vulnerabilities.

No application source was changed. Six pre-existing modified files and existing untracked documentation/skills were preserved. This directory contains new review artifacts only.

## Method and boundaries

- Read architecture, CLI/configuration, ingestion/orchestration, analysis/filtering, reporting/generation, device tooling, knowledge integrations, API and dashboard code. Review depth varied; this is not a claim of exhaustive verification of every branch.
- Parsed all 89 Python files in mobileag/config/tests successfully. Checked extracted dashboard JavaScript with `node --check`.
- Existing suite: `python -m pytest -q`: **79 passed, 4334 warnings, 42.60 seconds**. Most warnings were pytest-asyncio/Python deprecations, not application failures.
- Python 3.14.7, Linux 7.2.8-2-cachyos; base commit `fe1f26fd509c38a9fee8e0750b430cbc9d03bb12`. Installed setuptools 84.0.0, FastAPI 0.141.1, uvicorn 0.54.0, python-multipart 0.0.32, pyelftools 0.32. Source hashes are in `snapshot.json`.
- Custom reproductions use temporary synthetic files, TestClient, mocked ADB/LLM/orchestrator boundaries, and one researcher-controlled loopback HTTP listener. No real APK assessment, device exploitation, private-network probing, or cloud inference was performed for these reproductions. There is consequently no APK hash or Android build to report.
- Tests run against the installed local environment; clean-install dependency completeness and packaging were reviewed separately. No CVE or bounty eligibility claims are made.
- Security impact depends on reachability: the default web bind is loopback. Unauthenticated API behavior is confirmed, but internet exposure and cross-browser exploitation were not demonstrated.

## Reproduced issues

### 1. Upload path traversal and overwrite
**Location:** `mobileag/web/app.py:1503-1511`.

`file.filename` is concatenated directly with UPLOAD_DIR, then written using `write_bytes`. Neither containment nor exclusivity is checked. A multipart filename `../outside.apk` wrote the synthetic marker outside the temporary upload directory and returned HTTP 200.

**Prerequisite/impact:** Access to the upload endpoint. Write or overwrite files accessible to the server account, with filenames ending in an accepted .apk/.ipa/.zip suffix. This does not establish arbitrary-extension writes or host code execution. Absolute paths also discard the upload prefix by construction.

**Fix:** Assign server-generated opaque filenames, keep the original name only as metadata, enforce containment, reject symlinks, and create files exclusively. Stream uploads with byte limits and validate archive type.

### 2. Unauthenticated access to device-control APIs
**Location:** `mobileag/web/app.py:78-85,993-1164`, especially `1061-1065`; WebSocket `135-155`.

No authentication/authorization dependency guards these routes. An unauthenticated request dispatched `echo synthetic` to the mocked device-shell operation and returned 200. A supplied foreign Origin was reflected in the CORS response. WebSockets accept connections without an origin or authentication check.

**Prerequisite/impact:** Ability to reach the dashboard API and, for real device impact, an ADB-authorized connected device. The service exposes shell execution, install/root operations, logs and screenshots using its existing device privileges. This is not proof of Android privilege escalation or host-shell execution. Browser loopback/private-network restrictions were not tested.

**Fix:** Authenticate HTTP and WebSocket sessions; authorize each device/action; enforce exact allowed origins, CSRF protection and host validation. Keep loopback binding by default and require explicit opt-in for remote access.

### 3. Unauthenticated server-side network access
**Location:** `mobileag/web/app.py:1199-1231`.

Caller-supplied URLs reach an HTTP client with redirects enabled and `verify=False`. A request through TestClient retrieved a synthetic marker from a temporary server bound only to 127.0.0.1.

**Prerequisite/impact:** API reachability. An unauthorized caller can make requests from the scanner's network position and read returned data. URL probing is intended functionality for an authorized operator; the missing trust boundary makes it unsafe for untrusted callers. No cloud metadata or unrelated hosts were tested.

**Fix:** Require authenticated scope configuration and allowed destinations; validate resolved addresses and every redirect; set response/timeout limits. Verify TLS by default, with a clearly logged per-target override if needed.

### 4. `--offline` does not enforce offline operation
**Location:** `mobileag/cli.py:27,71-79`; `mobileag/llm/router.py:44-65`.

The flag changes the console message but not the settings/router used by Orchestrator. The CLI test passed a synthetic configured OpenAI key and `--offline`; the orchestrator still received `enabled_providers=['openai']`.

**Impact:** Real configured providers can still receive source snippets and incur charges despite the explicit no-cloud promise. The test mocked the orchestrator and did not send any source to a cloud service. DependencyScanner also has independent OSV networking (`dependency_scanner.py:59-76`), relevant if offline is intended to mean no egress at all.

**Fix:** Add an enforced network/LLM policy to the scan context, disable provider construction/routing, and gate external vulnerability lookups. Assert zero outbound calls in an offline integration test.

### 5. Missing files produce fabricated successful scans
**Location:** `mobileag/web/app.py:1616-1618,1764-1813,1817-1847`.

The real pipeline is entered only for existing files larger than 100 bytes. Otherwise a fallback generates three synthetic security findings and marks the scan complete. Submitting a nonexistent temporary .apk returned a completed scan with three findings.

**Impact:** Invalid input looks like successful security analysis. Tiny uploads trigger the same fallback. This is an evidence-integrity failure, not an actual vulnerability in any scanned app.

**Fix:** Validate inputs before creating jobs; return an input error for missing/invalid archives. Put demo data behind an explicit isolated demo mode and label every demo artifact.

### 6. Dashboard ignores final filtered findings
**Location:** `mobileag/core/orchestrator.py:137-140`; `mobileag/web/app.py:1593-1601,1623-1654`.

The orchestrator streams at most the first 15 raw findings before filtering. The dashboard appends those previews permanently and never reconciles against `filtered_findings`. A mocked scan streamed a rejected raw lead and returned a different final-only finding: the dashboard retained only `raw`.

**Impact:** Rejected leads remain visible, verified candidates may be missing, and final counts disagree with the exported filtered SARIF. Later telemetry calls the displayed total confirmed.

**Fix:** Keep previews separate; replace the final list and recompute statistics from the canonical final result. Preserve the status/evidence of each finding and surface incomplete/error states.

### 7. Markdown/JSON reporting is disconnected
**Location:** `mobileag/core/orchestrator.py:336-368`; `mobileag/cli.py:86-91`; `mobileag/reporting/report_engine.py:35-57`.

`_save_outputs` saves SARIF/scripts/guides but never invokes ReportEngine. The default CLI claims a report path although it remains empty, and Android `--format json` does not select JSON generation. A synthetic state produced only SARIF plus script/guide directories.

**Fix:** Invoke reporting explicitly for the selected formats, return actual artifact paths, and make reporting failures fail the requested operation. Add end-to-end tests for every CLI format. The separate `scan --ipa ...` branch also lacks a Markdown output branch despite Markdown being its default.

### 8. Resources and smali are dropped from the analysis root
**Location:** `mobileag/ingestion/apk_extractor.py:58-78,109-113`; `mobileag/core/orchestrator.py:179,228-241,270`.

APKTool writes resources/smali to `apktool_out`; JADX writes Java to `jadx_out` using `--no-res`. Orchestrator stores only jadx_out as the analysis root and passes it to resource, native, React Native and smali checks. A synthetic ingestion fixture with smali in apktool_out produced an analysis root with zero smali files.

**Impact:** The pipeline can announce analyses that never see their inputs; resource/asset/library checks can be silently incomplete. Exact coverage on a real APK was not measured.

**Fix:** Preserve distinct java/resource/smali/native paths in typed scan state and route each engine correctly. Record analyzed file counts and explicit skipped/error reasons; do not equate no inputs with clean results.

### 9. Frida deployment status does not prove execution
**Location:** `mobileag/dast/frida_runner.py:238-266`; `mobileag/web/app.py:1698-1713`.

`execute_script_payload` checks for a server and writes a file; it never attaches, spawns, loads or resumes an app. With mocked successful ADB calls it reports `deployed`, while recorded commands contain only `ps` and `echo`. The automatic scan path merely generates hook strings and discards them while announcing deployment.

**Additional static defect:** Interpolating JS into nested shell/echo strings does not correctly preserve double quotes, dollar expansions or arbitrary package names. Script-transfer integrity and shell injection require separate controlled validation; no shell payload was executed.

**Fix:** Use a safe file transfer and an actual device-specific Frida session, load the script, require a readiness acknowledgment, and distinguish generated/transferred/attached/executed/failed. Respect return codes.

### 10. API authorization checks manufacture confirmed vulnerabilities
**Location:** `mobileag/web/app.py:1282-1332`.

The API fuzzer promotes an `/admin/` substring to CONFIRMED CWE-285 and missing selected request headers to CONFIRMED CWE-306 without verifying authorization bypass. A supplied 403 Forbidden response still produced both confirmed findings.

**Fix:** Treat paths and missing headers as review leads. Confirm only using controlled authorized/unauthorized identities and demonstrated protected effects. Support cookie/session/mTLS authentication rather than assuming two header names define all auth.

### 11. Taint engine has both false negatives and false positives
**Location:** `mobileag/analysis/taint_engine.py:158-215,241-268`.

- `web.loadUrl(getIntent().getStringExtra("url"));` returns zero findings: early return at 181-182 prevents the later inline-source handler.
- Reading an extra into `url`, overwriting it with a constant, then loading it still returns one finding: taint sets only grow, never kill assignments.
- Static inspection also shows file-global variable names with no method/scope isolation or real call summaries, despite the inter-procedural label.

**Fix:** Remove the incorrect inline early exit, implement statement ordering and kill sets, isolate variable scopes, and use parsed control/dataflow plus explicit inter-procedural summaries. Add negative-control fixtures; label heuristic output unverified.

### 12. Qdrant storage crashes on the current Finding model
**Location:** `mobileag/knowledge/qdrant_store.py:65-77`.

`finding.cwe` is accessed although the model defines `cwe_id`. A mocked connected client with a valid Finding raises `AttributeError: 'Finding' object has no attribute 'cwe'` before the operation's try/except.

**Fix:** Use `cwe_id`, type-check payload creation and test storing current model instances. Historical filtering is additionally inactive in the main orchestrator: it supplies no Qdrant object and the filter supplies `embedding=None`.

### 13. iOS executable detection skips valid binaries
**Location:** `mobileag/analysis/ios_analyzer.py:80-90,449-452`.

The executable path is guessed from the .app directory name rather than CFBundleExecutable. A synthetic `Display.app` declaring and containing `RealExecutable` returns `binary_path=None`, silently skipping binary checks.

**Fix:** Read and validate CFBundleExecutable relative to the bundle, distinguish missing/unsupported binaries from clean results, and support tested Mach-O formats.

### 14. Deep-link schema mismatch disables intended dynamic coverage
**Location:** `mobileag/ingestion/manifest_parser.py:151-163`; `mobileag/web/app.py:1718-1725`.

Parser deep links have scheme/host/path/component; the worker reads `d.get('uri', '')`. Synthetic parsed deep links therefore become empty strings.

**Fix:** Use one typed deep-link schema and construct URI values once. Preserve component identity and validate nonempty targets before dispatch. Also restrict activity fuzzing to activities: the worker currently iterates all component types.

### 15. String-valued false LLM votes become true
**Location:** `mobileag/llm/consensus.py:140-150`.

`bool(data.get('vulnerable', False))` interprets the string `"false"` as true. Direct parsing reproduced this reversal.

**Fix:** Validate strict boolean/schema types and confidence bounds. Treat malformed responses as invalid votes; do not silently coerce them. Model consensus remains opinion, not exploitation evidence.

### 16. Packaging fails and web dependencies are undeclared
**Location:** `pyproject.toml:1-29`.

An isolated copy built using `pip wheel --no-deps --no-build-isolation .` fails metadata generation: multiple top-level packages discovered in a flat layout (see `packaging.txt`). There is no explicit package discovery/build configuration. FastAPI, uvicorn and python-multipart are imported/needed by the dashboard but absent from declared project dependencies; pyelftools is also absent for ELF support.

**Fix:** Define build-system, explicit package discovery for mobileag/config, template package data, runtime extras and development/test dependencies. Test wheel installation and dashboard startup in a clean supported Python environment, not the developer's pre-populated site-packages.

## Additional source-confirmed defects and investigation leads

These were not demonstrated as end-to-end exploits:

- **DOM XSS path:** `web/templates/index.html:1235` inserts toast messages using innerHTML. Calls at 2205/2222 interpolate uploaded filenames; 1932 interpolates scan metadata. Use textContent or safe DOM nodes. Attacker-controlled markup reaches an HTML sink by source inspection; browser script execution was not tested.
- **Ignored settings/options:** `web/app.py:872-881` edits only RUNTIME_SETTINGS, while workers instantiate environment Settings. `auto_taint` is assigned but never used, and RunScanRequest.output_dir is not passed to orchestrator.scan. UI success does not mean execution policy changed.
- **Failed ingestion can look successful:** Orchestrator returns state with errors instead of raising (`120-126`); the worker continues to final completion without checking those errors. CLI likewise prints scan complete and exits normally when state contains warnings/errors. Use explicit failed/partial/succeeded states and nonzero CLI exit codes for failed ingestion.
- **Unbounded work:** uploads fully buffer the request; jobs/ACTIVE_SCANS/telemetry have no quota, cancellation, concurrency limit or persistence. Archive extraction has no expansion budget; APKTool has no timeout. No resource-exhaustion test was run.
- **iOS uploads routed through Android:** web upload accepts IPA, but the real worker always invokes Android Orchestrator. IOSSecurityAnalyzer is imported but unused by that worker.
- **Secret persistence:** storage auditor retains full preference lines in code_snippet (`dast/storage_auditor.py:88`) despite a comment about masking. Full evidence can flow into results/telemetry. Redact secrets before persistence or broadcasting, and keep optional raw evidence encrypted and access-controlled.
- **Privilege-confused findings:** ProviderAuditor (`dast/provider_auditor.py:38-68`) calls ADB content query but describes returned rows as proof that ordinary applications bypass permission guards. SQL error strings likewise become confirmed injection without data-access impact. Record caller UID/permissions and use a separate ordinary-app harness; keep root/shell evidence distinct.
- **Native heuristics overclaim:** `analysis/native_analyzer.py:40-58` treats raw symbol-string presence as CONFIRMED vulnerability without a call site, attacker input, or unsafe usage. Report imports as leads, not proven command execution/memory corruption.
- **Docker exposure defaults:** compose publishes database ports without loopback addresses; Neo4j uses a literal password and Qdrant has no configured API key. Deployment was not started or externally tested. Bind locally and configure secrets/auth before any shared-host use.
- **Proxy correctness:** `dast/mitm_proxy.py:202-239` does not handle case-insensitive Content-Length, chunked request framing, exact-length fragmented reads, or arbitrary binary bytes correctly; full response reads lack a timeout/size limit. HTTPS CONNECT only tunnels encrypted bytes, not decrypted HTTP. Do not present it as full TLS interception. Prefer a maintained HTTP proxy/parser.
- **Other knowledge issues:** `knowledge/feedback.py:107` writes a literal backslash-n rather than a newline in training export. Main orchestration does not wire persistence/feedback into an actual historical-learning loop. Test output schemas and round trips.

## Recommended repair order

1. Fix upload containment and authenticate device/network APIs; constrain origins and target scope.
2. Remove implicit simulations and enforce offline/no-egress policy.
3. Establish a typed, persistent scan result with explicit evidence status, final finding reconciliation and failure handling.
4. Repair packaging, reporting, analysis paths and the taint/deep-link/IPA/Qdrant contracts.
5. Implement and verify real Frida attachment and device-specific instrumentation; separate privileged diagnostics from ordinary-app validation.
6. Add integration and negative-control tests for each finding above. Existing tests mostly exercise isolated helpers and can assert misleading success statuses rather than end-to-end effects.

## Reproduction artifacts

From the repository root (using the current installed dependencies):

```bash
PYTHONPATH="$PWD" python docs/audit-2026-10-05/checks.py
PYTHONPATH="$PWD" python docs/audit-2026-10-05/extra_checks.py
PYTHONPATH="$PWD" python docs/audit-2026-10-05/loopback_check.py
```

The first script uses temporary file writes and mocked ADB/provider calls. The second uses synthetic IPA/manifest/model fixtures and a temporary source copy for packaging; its build log destination is `/tmp/mobileag-review-20261005/packaging.txt` (create that directory before rerunning). The third opens only a temporary localhost listener and shuts it down afterward. Results are preserved alongside this report. These scripts reproduce current bugs; they are not passing regression tests for a fixed version.
