## Latest follow-up

See [followup-validation/README.md](followup-validation/README.md) for module extraction, actual compiled Android tool coverage, SDK/version corrections, and Genymotion timeout/cleanup evidence. Prior results below are historical to their pass; current unrooted-device and full production acceptance remain open.

# Current transformation status — 2026-10-05

## Executive summary

This is a **single-operator, loopback research workbench**, not a shipped Android/iOS banking/social app or a multi-tenant SaaS. Applicable security and workflow controls have been implemented and tested. This does **not** certify all source code, every uploaded app, all devices, WCAG conformance, or production deployment security. Original baseline findings and their evidence remain unchanged; this document supersedes their implementation status, not their historical observations.

### Implemented priorities (security and product controls, not ten invented vulnerabilities)

1. **P1 / C+D:** Uploaded static analysis leaves the API process. `web/jobs.py` uses bubblewrap with separate mount, PID and network namespaces; only runtime/modules, the selected read-only archive and a private job workspace are mounted. No home, dashboard SQLite, provider environment or device mount. No unsafe fallback.
2. **P1 / C+D:** Aggregate user-systemd cgroup limits: 3GiB memory, 512MiB swap, 128 tasks, one CPU core; supervisor wall timeout 360 seconds. Worker address-space, file-size, CPU and FD bounds plus output-size/file-count budgets. Cancellation kills the process group and stops its cgroup. The kernel, user manager and host tools remain trusted dependencies.
3. **P1 / B+C:** Persisted scope editor narrows environment device/origin ceilings; server checks exact actions, package IDs and replay methods. Default without saved scope is static-only. Explicit shell/root/install/Frida permissions are **device-wide**, not package confinement. These cannot be securely fixed through UI/UX alone; middleware/network enforcement is the minimum technical control.
4. **P2 / B+C:** Eight-hour process session TTL, rotation, logout, socket revocation/expiry checks and authenticated reconnect. Tokens stay in page memory. Restart with a fixed environment token reuses that configured credential; use generated per-process credentials when revocation across restarts matters. No registration/MFA system is fabricated.
5. **P2 / C:** Persisted original hash, request, analysis policy, version when available, bounded sequenced events and canonical results; restart marks unfinished jobs interrupted, never silently resumes device actions. Cancel and explicit immutable-artifact retry have UI controls. Concurrent submissions reserve at most two jobs in the supported single-worker event loop.
6. **P2 / B+C:** Explicit retention preview, exact scan-ID confirmation, revision/status compare inside SQLite transaction, output containment, symlink rejection, decision deletion and tombstone preventing legacy resurrection. Uploaded originals are deliberately preserved, including shared archives. No automatic destruction of original evidence.
7. **P2 / A+C:** No runtime CDN scripts/fonts: pinned local Vis/Chart/Lucide, precompiled CSS, licensed vendor files, integrity manifest and npm lock. CSP scripts are self-only without inline/eval execution. Style-inline remains necessary for current visualization/layout code; it is not permission for inline JavaScript.
8. **P2 / A:** Labelled native session dialog, wrong-token recovery, keyboard scan-modal containment/Escape/focus return, skip link, visible focus, semantic nav/live status, larger controls/text, stronger contrast, reduced motion, 320px reflow and textual attack surface. Automated axe checks cover the eight fixture views, not every state or assistive technology.
9. **P2 / B+C:** Unsupported/truncated iOS executable reports missing binary coverage; incomplete tool analysis retains useful **UNVERIFIED** candidates with partial/error status. Consensus, lexical sanitizers and default CWE score templates do not prove exploitation. Implicit device-wide log clearing was removed; deep links are package-targeted and active/destructive actions ask for confirmation.
10. **P2/P3 / C+D:** Lazy SDK/agent imports, summary pagination, bounded feeds, exact tested Python constraints, dependency evidence, pinned least-privilege CI actions, local asset rebuild/check scripts and packaged-wheel checks. GitHub CI has not been executed in this local validation.

A = screens/components/UX; B = server/API enforcement; C = code/architecture; D = environment/infrastructure. UI hiding is never authorization.

## Requirements coverage

| Requested area | Actual applicable implementation / assessment | Remaining acceptance boundary |
|---|---|---|
| 1 System understanding | Original attack-surface/architecture reports plus current OpenAPI inventory | No external backend assumed |
| 2 Mobile security | Existing manifest, storage, IPC, network and binary candidate analyzers; findings stay unverified | Current ordinary-app device proof required for uploaded-app exploit claims |
| 3 Data security | Private originals/SQLite/atomic snapshots, redaction, memory-only session, retention | Redaction is pattern-based, not a universal PII detector |
| 4 Network | Existing DNS-pinned scoped replay/TLS/no redirects; static worker no network | Deployment TLS is outside loopback product |
| 5 Client trust | Server triage revision, scope, archive/output and network gates | No multiuser/tenant authorization claim |
| 6 Business logic | Job reservation race regression, revision conflicts, explicit retry/deletion, no device auto-resume | Payments/subscriptions/referrals N/A |
| 7 Input/output | Typed/bounded requests, archive containment, text-safe handlers, resource-limited worker | Parser/native-tool zero-days cannot be ruled out |
| 8 Secrets/config | Keys stay server-side, worker receives none, public vendor/config distinguished | Rotation needed only if a real credential is found exposed; none invented |
| 9 Dependencies | Tested Python snapshot, pip-audit, pinned npm/runtime assets and build-only warning review | Advisory absence is not reachability proof or future safety |
| 10 Platform | Android/iOS static analyzers, actual package/version metadata and explicit coverage | No real device/OS build supplied; iOS entitlements/runtime not fully assessed |
| 11 Privacy | No new analytics, default offline, explicit cloud CLI approval, redacted evidence and deletion | Human review for unusual sensitive source/PII remains required |
| 12 UI/UX | Eight real views; session/scope/recovery/retention/readiness controls | Researcher/user usability study not performed |
| 13 Accessibility | Labels/focus/contrast/targets/reduced motion/text graph; automated fixture checks | Screen reader and all-state manual conformance audit required |
| 14 Security UX | Exact-scope warnings, explicit dangerous-action confirmation, safe expired-token reconnect | A confirmation is consent UX, not a server permission |
| 15 Performance | Lazy SDKs, pagination/feed bounds, isolated job budgets; measured cold import | Large-corpus benchmark, battery/native-mobile metrics not established |
| 16 Error paths | 401/403/409/413/422/429, partial/error/interrupted/cancelled, fail-closed tools | Real deployment outages and device recovery not simulated as successful proof |
| 17 State matrix | Current matrix below; offline/error/no-data/retry and N/A states separated | Permission-denied device states require controlled-device acceptance |
| 18 Design system | Shared local CSS primitives and existing reusable palette/components | Larger JS route/render-module refactor remains maintainability work |
| 19 UI-only separation | A/B/C/D above; technical enforcement explicit | Server/host controls cannot be replaced with UI |
| 20 Prioritization | Evidence-based P1/P2/P3 controls and release gates | No unsupported P0, CVSS or bounty eligibility claims |
| 21 Finding format | Original detailed security report preserved; fix status linked to locations/tests | Leads remain leads unless impact is reproduced |
| 22 Screen review | Original screen findings plus current state matrix | Not invented onboarding/payment screens |
| 23 API matrix | `CURRENT_API_MATRIX.md` + current OpenAPI JSON | External APIs not present in code not invented |
| 24 Overall score | Original baseline scores retained as historical judgments | No new universal numerical risk score without coverage; not a certification |
| 25 Roadmap | Phases below with remaining release gates | External acceptance gates remain open |
| 26 Fix/test workflow | Implementations + negative/control/unit/browser/namespace/cgroup tests | Tests are scoped evidence, not proof of absence of bugs |
| 27 False positives | Static candidates, tool failures and dependency warnings distinguished | No root/shell/Frida result recast as ordinary-app exploitation |
| 28 Deliverables | Original full audit + current inventory/status/evidence and checklist | Do not read “implemented” as “every requirement proven in production” |

## Current screen state and design matrix

| Screen | Main improvements / previous problem | Loading / empty / errors / retry | Authorization / offline / partial | UI-only? |
|---|---|---|---|---|
| Connect | Replaced blocking token prompt with labelled native dialog | Invalid-token alert, disabled submit while checking, retry | Expired token clears memory and reconnects; offline fetch failure stays recoverable | UX A; authentication B/C |
| Surface | Honest assessment status + text alternative to graph | Existing upload/loading; no selected scan message | Status/errors/coverage exposed; no clean/100% assurance from zero findings | A + C |
| Findings | Safe byte-exact copy, durable scoped triage and evidence-aware exports | Empty/filters, missing evidence, conflicts recover by reload | All candidates unverified; partial findings retained; confirmation requires notes | A + B/C |
| History | Summary pagination, counts, no-data message, job/retention controls | Load/failure, cancel/explicit retry, original hash recheck | Interrupted/error/partial/cancelled distinct; active evidence cannot be purged | A + B/C |
| Agents | Capabilities rather than fabricated execution/health | No fake findings; disabled unsupported capabilities | Static offline defaults; model SDK only explicitly approved CLI flow | A + C |
| Settings | Persistent exact scope, readonly offline policy, readiness, rotate/logout | Save/validation/scope-ceiling errors and reload | Scope rejected server-side; device-wide permission warning; no key editor | A + B/C/D |
| Device diagnostics | Explicit device/package/actions; no implicit log deletion | Missing device/error/native-tool unavailable; manual retry | Denied scope is 403; dangerous actions require confirmation; real-device test open | A + B/C/D |
| Taint | Heuristic explanation rather than runtime sink proof | Source-required/typed input, bounded timeout and error | Missing source/runtime not assessed; offline compatible | A + C |
| API review | Capture analysis named separately from live replay | No endpoints/response not observed; target error has no fake success | Exact origin/method approval; private destinations extra opt-in; no redirects | A + B/C/D |

Permission-denied native-mobile states, push, MFA, subscriptions and payments are not workbench screens. Ordinary Android shell diagnostics are not app-level authorization verification.

## Final supported flow

Connect with terminal token → check readiness → save narrowed authorized scope if device/replay work is needed → upload original → isolated offline static job → review actual coverage and unverified candidates → record controlled reproduction notes and revisioned analyst decision → export canonical evidence → preview/confirm selective output deletion. On interrupted jobs, explicitly retry only if the original hash still matches. Device and live replay operations are separate deliberate workflows.

## Architecture and remaining roadmap

Current: API/auth + SQLite authoritative state + isolated static process/cgroup + mounted input/workspace + canonical report generation + local UI assets. Secrets are not parser inputs; cloud execution is not granted by a hidden checkbox.

- **Phase 1/2 — implemented controls:** preserve prior critical fixes, scope/auth/input/network boundaries, private storage, explicit action consent, offline isolation and resource limits.
- **Phase 3 — implemented service boundaries / remaining refactor:** jobs/policy/repository isolated modules; route file and legacy JS remain large. Further router/render-module extraction is P3 maintainability, not an invented exploit.
- **Phase 4/6 — implemented UI foundations:** shared accessibility styles, labelled workflows, recovery, text graph and fixture accessibility fixes. Manual assistive-technology/usability acceptance remains open.
- **Phase 5 — implemented bounds / measured smoke:** pagination/lazy imports/bounded events and job budgets. Representative large APK/native corpus load testing remains open, rather than extrapolating from tiny synthetic fixtures.
- **Phase 7 — final release gates:** packaged-wheel regression, clean evidence/source hashes, advisory review, no real credentials in publication, CI execution, and authorized ordinary-app/device acceptance.

### Required gates before a production claim

- [ ] Run the shipped app/package on authorized current unrooted devices; record serial pseudonym, OS build, package version and APK hash. No such device was provided here.
- [ ] Validate Android real-tool parsing/decompilation on a representative researcher-owned APK corpus; namespaces/cgroup and synthetic IPA are not complete decompiler coverage.
- [ ] Manually test screen reader, keyboard, zoom and all modal/error/permission states; axe fixture success alone is not WCAG certification.
- [ ] Run representative throughput/startup/corpus benchmarks and failure/recovery soak tests; current measurements are smoke tests.
- [ ] Execute the checked-in GitHub CI on the intended release branch. Local runs are not remote CI results.
- [ ] Keep one loopback operator/one API worker. Remote/multiuser hosting is unsupported until an identity/tenant architecture and deployment TLS/operational controls are designed and tested.
- [ ] If web cloud analysis is required, implement a separate least-privilege credential/data broker; **this cannot be securely fixed through UI/UX alone**. Current web workers intentionally reject cloud egress.

A request to fix everything cannot justify fabricating an ordinary-app exploit, a platform feature that does not exist, a numerical risk score, or a production-readiness certification.

## Authorized automation follow-up (2026-10-06)

See [`../automation-2026-10-05/README.md`](../automation-2026-10-05/README.md) for the new bounded Android navigation/read-only API workflow, API inventory and validation. Earlier evidence remains unchanged. This follow-up does not close the current-unrooted owned-app, representative corpus, manual accessibility or production readiness gates.

## Primary guided workflow and provider broker (2026-10-06)

[`../guided-assessment-2026-10-06/README.md`](../guided-assessment-2026-10-06/README.md) records the primary upload/scope/start flow, optional advanced tools, separate metadata-only provider broker, real isolated SAST/loopback integration and open gates. The parser still has no network or provider credentials. This broker is not raw APK/source cloud analysis or an executable LLM agent.
