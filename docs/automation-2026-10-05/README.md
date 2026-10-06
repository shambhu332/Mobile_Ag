# Authorized automation implementation and validation

Updated 2026-10-06. This extends the existing workbench fixes; it is a **bounded Android/read-only API MVP**, not completion of every platform and workflow in the requested autonomous-agent specification. The earlier review, original artifacts and findings remain in `docs/product-security-review-2026-10-05/`; they are historical evidence, not new target findings.

## Executive summary / application map

Dashboard session → security middleware (bearer, expiry, Host/Origin, body limits) → automation router → explicit saved policy intersected with server scope → orchestration service → dedicated-device Android adapter / pinned scoped HTTP transport → private revisioned SQLite → redacted report, structural SVG and coverage. No LLM decides or executes device actions. No API is discovered by probing unrelated hosts.

Review locations: `mobileag/automation/{models,routes,engine,android,store,report}.py`; `mobileag/web/app.py` integration and lifespan; `mobileag/web/policy.py` authorization; `mobileag/web/static/automation.js` review/approval UI; `mobileag/dast/adb_manager.py` bounded/cancellable child commands. Importing policy/contracts no longer eagerly constructs the server through `mobileag/web/__init__.py`.

## Supported end-to-end workflow

1. Start locally: `python -m mobileag.cli web --host 127.0.0.1 --port 8080`.
2. Enter the **workbench session access token** from that server terminal. It is not a GitHub password, app login, or AI key. The connection dialog now includes this explanation. Configured `MOBILEAG_API_TOKEN` is not printed; the owner supplies that configured value. Tokens stay in page memory; restart/rotation/expiry require reconnection. Authentication was not removed to hide invalid-token errors.
3. Configure exact authorized serials/origins in `MOBILEAG_ALLOWED_DEVICES` / `MOBILEAG_ALLOWED_ORIGINS`. Loopback/private fixtures additionally need `MOBILEAG_ALLOW_PRIVATE_TARGETS=1`. Save narrowed Settings scope: devices, packages, origins, methods and actions. `automation_observe` and `automation_execute` require the exact package and serial. Explicit launching needs separate `launch` authorization.
4. Open **Authorized Automation**. Provide the exact package/component, dedicated device/account confirmations and synthetic/dedicated-staging environment. Observe only the current approved foreground app.
5. Inspect controls, coordinates and hashed locators against the actual dedicated device. Select exact safe navigation/scroll actions and read-only API cases; type the run ID to approve. Unknown semantics, ambiguous/missing locators, form entry, toggles, dangerous/consent controls and outside-package dialogs are blocked. New controls never get implicitly approved. Locator movement heals only the same unique approved locator/class; changed screens or ambiguity stop execution.
6. Import operator-observed GET/HEAD metadata if desired. No arbitrary hosts, redirects, write APIs, captured credentials or implicit authorization reuse. Supply a dedicated test Authorization header afresh when needed; HTTPS is mandatory except explicit loopback fixtures. The field clears after submission.
7. Execute a bounded batch, stop if needed, export redacted evidence, review generated vs actually executed cases and untested reasons. Re-establish the state manually and prepare a new run with a parent ID for regression comparison. Restart marks active runs interrupted; **never resumes input**. Capture URLs must be re-imported after restart.

ADB input is **device-wide**, and pre/post foreground checks are non-atomic TOCTOU guardrails, not package isolation. Dedicated-device authorization is required. Do not use this on a shared personal/production device. An acknowledged input cannot be undone by cancellation. Label allowlists do not prove a server operation is read-only; the operator must confirm the intended workflow and endpoint semantics.

## Capabilities mapped to the request

| Requested area | Implemented / evidence boundary | Remaining work |
|---|---|---|
| Orchestrator/state/map/navigation | Durable run state, bounded graph, explicit action approval, tap/scroll/optional Back, fresh unique locator matching | Credential/forms, unbounded autonomous exploration, native iOS |
| Test generation | Eight variants per discovered control, risk annotations, explicit blocked reasons; baseline/anonymous/query variants for imported API requests | App-specific assertions/data/state adapters; generation is not execution |
| API/cURL testing | Exact scoped GET/HEAD replay, bounded query removal/empty/128-character boundary, separate fresh test header, timing/status/schema shape; environment-variable cURL placeholders | Writes, payment/business transactions, paired-account ownership fixtures, replay/session refresh workflows |
| UI/API correlation | Operator-imported action linkage with provenance | Transparent capture/causal correlation; no TLS bypass added |
| Authentication states | Operator-declared state, dedicated-account confirmation, protected anonymous 401/403 assertion | Actual MFA/OTP/logout/refresh/locked-state orchestration and ownership proof |
| Failures/evidence | Stop/error/interrupted status, action sequence, timestamps, graph, redacted structural layouts, API receipts | Crash/ANR instrumentation, screenshots requiring a separate privacy design, source correlation to app code |
| Security observations | Anonymous 2xx on declared protected endpoint = informational investigation lead, never a confirmed vulnerability | Server-side ownership/impact confirmation, sensitive storage/log/runtime analysis |
| UX/accessibility | Potential unnamed-control observations; automated workbench browser checks | App contrast, clipping, focus, screen reader, dynamic text and state-specific UX verification |
| Performance | Driver/snapshot/API elapsed measurements with overhead disclaimer | Native startup/rendering/memory/battery, representative workload/soak benchmarks |
| Regression/coverage/report | Executed receipts, untested reasons, report sections, before/after assertion comparisons | App-specific root-cause verification and wider workflow coverage |
| Safety/recovery | Scope checked before/after actions, expiry/revocation stops, bounded child output/cancellation, no auto-retry of issued operations | Deployment/multi-tenant architecture; current supported deployment is one local operator/one worker |

Limits: at most 30 UI steps/run, 10 requests/run, 120 seconds/batch, two concurrent devices, 0.5–10 seconds/request interval, 60 screens, 1,500 total nodes, 80 actions/observations, ten imported captures, 100 retained runs and 1 MiB/run document. Retention currently requires operator-managed export/offline backup; there is no automated destructive run purge. Hierarchy dumps use unique temporary names, read bounded output, and remove only their own temporary file. No root/su, hooks, consent acceptance, app-data clearing, device log clearing, account creation or unrelated-package operations are introduced.

## Privacy and evidence semantics

Raw hierarchy text, editable values, screen pixels, API bodies, cookies/headers, URL paths/query values, captured credentials and signing keys are not persisted by the automation engine. Only curated navigation names are exposed; arbitrary names/IDs are hashed. Schema values become type names and unknown schema keys are hashed. This is data minimization, not a claim of anonymization: hashes can reveal equality and guessable names. Approved origin/device/package/build metadata remains sensitive configuration and is accessible to the authenticated local operator.

Imported request metadata/correlations and auth state are explicitly operator-declared. API shape and status do not prove protected-data access. A navigation “passed” receipt means input acknowledgement plus observed in-package hierarchy, **not** business-flow or security correctness. Query cases without an oracle are “observed”, not passed. Missing credentials/budget/response means inconclusive/not executed. Regression “Fixed” means a failed assertion later passed, not a security root cause is proven fixed. Production-readiness score stays **null**, confirmed-security-issue count stays zero for this observation-only classifier.

Automation contract errors return a generic 422 instead of Pydantic's raw input-bearing validation payload; malformed payloads carrying an ephemeral header cannot echo it into UI/report evidence. Adapter errors are sanitized. Device locks/tasks release even when adapters or evidence persistence fail; interrupted durable state can be recovered without replay. These are implemented hardening/reliability controls, not invented production-app vulnerabilities.

## Workbench UI state matrix

| Screen | State/UX behavior | UI-only? |
|---|---|---|
| Connect | Native labelled dialog, terminal/config token help, invalid/expired/offline recovery | Help is UI-only; bearer/expiry are backend/code |
| Automation setup | Explicit targets/budgets/dedicated confirmation, disabled submit during observation, no implicit selection | UI plus backend scope/validation |
| Plan | Blocked reasons, exact control selection, run-ID confirmation, empty/no-run state | Approval UX plus server-side enforcement |
| Running | Polling, explicit Stop, duplicate execution disabled, revoked scope/timeout/error reported | UI plus engine/device controls |
| Evidence | Keyboard-scrollable redacted report, executed/untested separation, export/refresh | UI plus private storage/redaction |
| Regression | Parent run, manual state preparation warning, no automatic app-data reset | UI plus evidence-aware comparison |

Security, scope, TLS, authorization, redaction and durable-state controls **cannot be securely fixed through UI/UX alone**. UI changes communicate/collect approval; backend/API code must enforce it. Infrastructure must maintain loopback deployment, local access security, dependency/build integrity and scope ceilings.

## Validation and reproducibility

See `validation/` for actual test/browser/wheel/device results, hashes and limitations. Unit tests use synthetic UI adapters; the API tests contact only owned temporary loopback HTTP fixtures. Browser validation exercises the real auth/router/service/SQLite through a synthetic driver, not ADB. Original failed attempts are preserved separately.

```bash
python -m pytest -q
python scripts/verify-dashboard-assets.py
python -m build --wheel
# Install wheel with --no-deps --target into a temporary directory, then run
# scripts/wheel-smoke.py outside the checkout with PYTHONPATH set to that target.
python tests/browser_product_regression.py --server-python /path/to/venv/bin/python \
  --chromium /path/to/chromium --axe assets/node_modules/axe-core/axe.min.js \
  --output /path/to/private-evidence
# Opt-in ONLY after choosing an authorized dedicated serial:
PYTHONPATH="$PWD" python tests/automation_device_regression.py \
  --serial '<explicit-serial>' --output /path/to/private-fixture-evidence \
  --apktool-jar /path/to/trusted/apktool.jar
```

The opt-in fixture harness refuses an existing fixture package, compiles/signs its own permission-free app using an ephemeral key, records APK hash and OS metadata, installs/launches, approves one navigation, observes the graph, and uninstalls only that fixture. Do not substitute an unrelated APK/package or infer ordinary-app authorization from ADB integration.

## Prioritized transformation plan / remaining release gates

- **P1 security validation:** obtain actual owned APK/package, exact staging origins, dedicated account identifiers and a current unrooted device. User's generic “yes” supplied none; no production/staging target was contacted. Add paired-account assertions for server ownership before claiming BOLA/IDOR or fixes. Server authorization cannot be implemented by hiding UI controls.
- **P2 architecture/QA:** app-specific form/state adapters with synthetic data and explicit impact approvals; crash/ANR evidence collection with privacy boundaries; causal network adapter without blanket TLS bypass; supported iOS adapter if an authorized IPA/device is supplied.
- **P2 UX/accessibility/performance:** manual assistive-technology acceptance, native screen states/contrast/clipping, large owned APK corpus parsing, throughput/recovery/soak benchmarks. Automated workbench axe results do not certify all mobile screens.
- **P3 maintainability/operations:** further route/render refactoring, operator-safe run retention UI, approved integration adapters. Do not silently expand single-operator loopback deployment into remote multiuser hosting.
- **Final hardening:** full unit suite, ordered local assets, installed wheel, browser workflow, explicit fixture cleanup, exact commit CI, reproducible evidence. These check the implemented subset—not absence of every vulnerability or fulfillment of every requested feature.

No fabricated top-ten vulnerabilities, numeric security score, bounty eligibility or production-ready declaration is provided when the supplied evidence does not support it.
