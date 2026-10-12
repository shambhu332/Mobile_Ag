# Accuracy foundations — implementation status

This batch improves the existing pipeline, not the number of agents. It does **not** complete the full accuracy roadmap.

## Implemented

- Location-aware synthetic evaluation with TP/FP/FN, duplicate and execution-error accounting, corpus/source hashes, and exact-source overlap checks.
- Conservative guided coverage ledger: execution, operator-declared authentication, observed device metadata, and independently verified coverage remain separate.
- Export evidence contract: unsupported CONFIRMED claims become UNVERIFIED in reports without changing stored triage. Valid confirmation records remain analyst attestations, not independent exploit verification.
- Structured static source/sink metadata, explicitly unresolved guards and runtime verification.
- Narrow Java primitive-only SQL concatenation suppression. Numeric smoke/holdout labels were corrected; the public holdout is no longer described as blind.
- Offline, scoped comparison of operator-imported synthetic paired-account captures. Positive/negative controls compare exact JSON marker values. Only reduced results are persisted; no requests are sent and identities are not independently verified.
- Retest language distinguishes an assertion now passing from a verified root-cause fix. Dashboard scores no longer invent an 8.8 fallback.

## Validation

Local validation on 2026-10-11:

- Full pytest suite: **565 passed** (27,891 warnings remain).
- Location-aware corpus: **2 TP, 0 FP, 0 FN, 0 failed cases** in each of AST and lexical modes. These six small source fixtures are candidate-flow regressions, not a real-world accuracy estimate or exploit benchmark.
- Isolated Playwright renderer regression: passed; no browser errors.
- Python compilation, dashboard asset validation, and git whitespace checks: passed.
- Changed-file credential-pattern scan: no matches; this is not a guarantee of secret absence.

Reproduce:

```bash
python -m pytest -q
python scripts/evaluate-accuracy.py --corpus tests/fixtures/accuracy_instances.json
python scripts/evaluate-accuracy.py --corpus tests/fixtures/accuracy_instances.json --lexical-only
python scripts/verify-dashboard-assets.py
python tests/browser_accuracy_regression.py --chromium /path/to/chrome
```

## Remaining work

A truly blind external corpus, comprehensive interprocedural/guard reasoning, deeper Android validator families, authenticated role/workflow coverage, controlled live paired-account execution, independent artifact-bound runtime proof, root-cause deduplication, and broader native/iOS analysis remain incomplete. The export evidence gate is not a claim that every raw/live UI ingestion path has been normalized. No live application, device, API target, or model provider was tested in this batch.

## Continuation: dashboard evidence integrity

The follow-up batch extends presentation checks beyond exported reports:

- Scan detail and compatibility-list responses revalidate confirmations against the scan's APK hash, package and app version. Bare legacy confirmations become UNVERIFIED in presentation only; SQLite decisions and original dashboard files remain unchanged.
- Confirmed-severity KPIs require the server's checked analyst-attestation assessment. Live static/dynamic events cannot elevate themselves, even when carrying a forged confirmation status or assessment envelope.
- Triage receipts include the server-prepared finding. Both triage handlers consume that receipt and refresh KPIs; rejected or malformed receipts leave local status and revision unchanged.
- Runtime observations remain UNVERIFIED. These checks do not independently verify a claimed exploit.
- Cancelled paired-account evidence imports return HTTP 409. Negative controls cover APK mismatch, running/cancelled assessments, policy/environment revocation, unprotected capture, unapproved method, and duplicate JSON keys.
- The isolated renderer/triage browser regression is now included in CI.

Follow-up local validation (synthetic/mocked/loopback only):

- **584 pytest tests passed**; 28,508 warnings remain.
- Console browser regression: passed, including forged live-confirmation rejection, unchanged upload-only authorization boundaries, and local automated accessibility checks.
- Isolated renderer and triage receipt regression: passed with no page errors.
- Compilation, dashboard assets and whitespace checks: passed.
- Wheel build and installed-wheel smoke outside the checkout: passed (21 shipped scripts, 5 stylesheets, unauthenticated API access denied).

Review locations: `mobileag/reporting/evidence_contract.py`, scan/triage response paths in `mobileag/web/app.py`, and `workspace.js`, `telemetry.js`, `findings.js`, `dast.js`. Paired-evidence cancellation handling lives in `mobileag/assessments/routes.py`.

This closes the identified scan-presentation/live-KPI gap, not every possible future ingestion path. The deep semantic, authenticated workflow, independent runtime validation and external benchmark work above remains unfinished.
