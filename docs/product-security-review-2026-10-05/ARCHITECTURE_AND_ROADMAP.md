# Architecture, transformation plan and release gates

## Current architecture → problem → target design

| Current | Problem / trade-off | Recommended design | Minimum unavoidable work |
|---|---|---|---|
| CLI + FastAPI global single-operator state | Practical local prototype; not multiworker/multiuser-safe; settings/jobs disappear; shared bearer is deliberate admin capability | Keep local mode explicit. Modular API service with typed domain services. Add identity/tenant model only if shared use is actually required | B/C: job/config/evidence repositories; D: deployment profile |
| `web/app.py` combines huge demo data, endpoints, settings, callbacks and device dispatch | Review difficulty; duplicate policy and side-effect boundaries | Routers for scans/evidence/devices/replay/config; one scope-policy service; service-layer validation independent of HTTP | C: split module incrementally without breaking auth middleware |
| Single4240-line HTML script with globals/inline handlers | XSS contexts, stale selectors, inconsistent state, CDN trust | Small typed client modules/components; central safe API client and state machine; bundled assets; safe DOM events | A/C: fix S01/P01 now before framework migration. A new framework is optional, not itself a security fix |
| Filesystem JSON plus `ACTIVE_SCANS` and separate runtime ring | Split-brain triage; no instance identity; disk lists carry full reports | Local SQLite metadata/evidence index with transactions and scan-scoped UUIDs, immutable raw evidence files; revisioned exports | B/C: canonical status, audit history and recovery. Use Postgres only when deployment warrants concurrency |
| FastAPI BackgroundTasks / in-process heavy analysis | No durable queue/recovery/cancel, parser blast radius, event-loop blocking | Worker process + durable job table; isolated per-job workspace, deny-network default and quotas; worker emits structured events | B/C/D: sandbox and job lifecycle; avoid adding a distributed queue before needed |
| Detector scores, heuristic suppression, generated prose | Confidence/status/observed impact conflated, false positives/negatives | Domain objects for Observation, Candidate, ValidationRun, EvidenceArtifact and AnalystVerdict; explicit coverage/skipped reasons | B/C: no generated or heuristic content can create a captured-evidence record |
| ADB serial allowlist, broad operator commands | Good outer gate; no automatic per-app action scope; crawler unsafe | Project scope + explicit device/package/action plan; foreground checks and safe read-only default; capability-gated privileged actions | B/C: checks at execution step; A: target/permission review |
| Exact-origin HTTP replay with DNS pin/TLS/no redirect | Useful existing boundary; origin does not imply permitted business action | Preserve gate; per-project allowed origins/methods/test profiles; no automatic destructive replay | B: policy; A: explicit live-versus-capture UI |
| LLM router fallback/consensus | Raw target secrets/source can cross processor boundary; online flag not obvious | Offline-first; egress redaction and consent allowlist at router; provider data contracts and usage budgets | B/C/D: enforceable egress and scoped secrets; A: data-flow preview |
| Optional Neo4j/Qdrant helpers | Availability can look like validated graph/historical learning; unnecessary infra burden | Embedded graph from canonical evidence sufficient for local mode; optional projection behind interface; mark historical not configured | C/D: features only advertised when actually wired and validated |
| Unlocked Python deps / runtime CDNs / old image tags | Reproducibility and dependency assurance incomplete; old is not automatically vulnerable | Lock deployable dependency set + hashes, bundle browser assets, signed/digest-pinned images, SBOM, update/retest cadence | C/D: reproducible builds and CI scanning |

## Privacy and secret classification

| Data | Why collected / destination | Who can access | Classification and action |
|---|---|---|---|
| Target package/version, API origin, public Firebase/Google client config | Asset identity and route discovery -> report/browser | Bearer operator and report recipients | Usually public/nonsecret config; presence alone not a vulnerability; sensitive project metadata in some engagements |
| APK/IPA, decompiled strings, source snippets | Static analysis -> local uploads/output, optional model prompts | OS account, bearer, enabled processors, exports | Potential credentials/PII/proprietary code; preserve immutable originals privately, minimize egress and exports |
| LLM service keys, DB passwords, Qdrant/proxy/session bearer | Server/provider authentication -> environment/process | Server operator and authorized service | Secrets/credentials, never return in UI/API or commit; rotate if actually exposed, scoped/revocable where available |
| Embedded signing/private/encryption keys in targets | Security evidence, never needed for normal UI | Restricted evidence reviewers | Cryptographic material; redact reports, avoid cloud prompts; recommend target-owner rotation only after confirming live relevance |
| API replay headers/cookies/body, device logs/memory/screenshots | Controlled validation -> target and operator views | Bearer operator; possibly report recipient | Tokens/PII; synthetic accounts, minimize collection, explicit capture/reveal, retention and no-store |
| Generated source/PoC text and confidence | Analyst assistance -> reports/UI | Operator | Untrusted generated content, not evidence and not safe executable input |
| Known-key pattern matches in current tracked tree | Scanner detection/demo/test fixtures | Source readers | Eight locations recorded without values; contexts are demo/test. No live credential validity tested or confirmed. This is not a historical git secret audit |
| Default sample Postgres URI / example device/package names | Development defaults | Source readers | Placeholder configuration, not proven real account credentials; remove misleading defaults from production UI |

No separate analytics SDK/crash-reporting SaaS integration or payment/push/account system was identified in the project entrypoints. Public CDN/font requests do expose browser network metadata to those asset services; do not equate offline analysis mode with fully offline browser operation.

## Dependency and supply-chain evidence
- `evidence/python-dependencies.json` records the validation environment; local `mobileag` excluded from external lookup. On2026-10-05, the [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/) returned **zero advisory matches for108 public installed packages**, with no pending pages (`dependency-osv.json`). Only package names/versions were transmitted, not source, artifacts or credentials.
- This is a point-in-time catalog result for one installed environment, **not proof of zero vulnerabilities** and not proof every dependency is reachable in deployment. Python extras/build/test dependencies are included; package declarations have no reproducible lock.
- `pyproject.toml` has unpinned dependencies and providers initialized by optional keys. Optional Frida/native parser integrations were not installed/tested on a real device in this review.
- `docker-compose.yml` declares Neo4j5.12.0 and Qdrant1.6.1 tags, loopback port bindings and required auth environment values. No running-image SBOM/advisory/reachability audit was performed; do not label old versions exploitable from age alone. Verify supported versions/digests in the chosen release environment before shipping.
- Browser assets use mutable CDN URLs; no authoritative installed JS version lock/SBOM exists. These were not covered by Python OSV results.
- No CI workflow directory was present in the inspected tracked tree. Add package/build/browser/negative security tests and dependency/secret checks, not just a dependency badge.

## Prioritized transformation plan

Change classes: **A** screens/components/flows; **B** server/API enforcement; **C** architecture/implementation; **D** configuration/infrastructure. Even A requires frontend implementation unless an existing UI setting actually supports it. No imaginary no-code capability is promised.

### Phase1 — Immediate critical-security gate (P1 here; no confirmed P0)
1. **S01 — Safe renderer first [A/C, medium]:** remove data-bearing inline handlers across all workbenches. Until fixed, do not use hostile-sample copy/run actions. Acceptance: synthetic browser payloads remain inert and copied data matches input.
2. **P01/P02 — Restore truthful core UI [A/B/C, low/medium]:** fix missing DOM selector; remove seeded metrics/fake verified evidence, canned observed exploits and no-op run success. Acceptance: exact API totals, Not assessed/Not collected states, no fabricated runtime claims.
3. **S02 — Protect confidential online input [A/B/C/D, medium]:** retain offline mode until central egress policy and consent are in place. Acceptance: provider transport never receives sentinel secrets; offline generates no analysis egress.
4. **S03/P04 — Safe DAST [A/B/C, medium/high]:** stop implicit device selection and automatic consent; package-bound execution, dry-run plan. Acceptance: wrong foreground causes zero commands; scope enforced server-side.

**Gate:** browser and boundary probes fail on baseline and pass after fix; retain old evidence as baseline, write post-fix evidence separately. No claim that these items have been fixed by this audit.

### Phase2 — High-risk security and evidence integrity (P1/P2)
- S04 transactional scan-scoped triage and audit history; immutable rule/instance separation [B/C].
- S09 nested validation and predictable errors; scope-policy reuse for all device/install routes [B/C].
- S06 bundled assets and CSP/response headers [C/D].
- S08 private artifact modes, redacted default views and retention APIs [A/B/C/D].
- S10 explicit local-only deployment boundary; TLS/session/role design only if remote/shared use required [B/D].

**Gate:** API/WS negative auth, scope, quota, malformed-input and persistence regressions; exports agree with canonical record after restart. UI hiding never counts as authorization.

### Phase3 — Architecture and analysis accuracy (P2)
- Worker isolation, typed jobs, progress events, cancellation, restart recovery and bounded queues [B/C/D].
- Separate source observation, candidate, validation/evidence and analyst verdict schemas; keep raw/suppressed candidates [B/C].
- Replace S05 generic sanitizer scoring with specific defensible rules; calibrate static detector claims against positive/negative corpus [C].
- Split monolithic API/client modules; optional graph/LLM adapters with explicit readiness [C].

**Gate:** model/DB outages produce skipped/partial states; candidate suppression is explainable; worker crash cannot produce a completed-clean report. Full semantics is longer-term; disable unsafe suppression immediately rather than delay all relief.

### Phase4 — UI/UX redesign (P2/P3)
Implement the nine-step workflow in `UI_UX_REVIEW.md`. Prioritize Connect, Readiness/Scope, Upload/Review, Findings/Evidence and export/triage. Create shared design components and status/error vocabulary; remove dead controls. Use scope IDs/effective config, not manual backend edits per scan [A plus B for missing capabilities].

**Gate:** new operator completes a synthetic static scan/review/export using UI only; DAST/API replay remain explicitly opt-in; every unsupported capability explains why.

### Phase5 — Performance and reliability (P2)
Paginated history summaries, indexed metadata, off-event-loop analysis, bounded telemetry DOM, batch graph updates, debounced searches, cached readiness and budgeted retries [A/B/C]. Enforce total input/spool/expanded/output budgets; timeout/cancel all expensive work [B/D].

**Gate:** benchmark fixed synthetic workloads with measured latency/memory/disk budgets agreed for target hardware; no fabricated performance claims. Collect baseline before setting release thresholds; preserve responsive UI and bounded event-loop delay during analysis.

### Phase6 — Accessibility (P2, integrated earlier where possible)
Labels, keyboard/screen-reader interactions, semantic dialogs, focus order/restore, visible focus, status announcement, responsive reflow, larger targets, reduced motion, text contrast and graph alternatives [A].

**Gate:** keyboard-only core workflow, screen-reader smoke on selected supported platform,320px and200/400% zoom coverage, actual computed contrast/target-spacing verification. Automated audits supplement—not replace—manual assistive testing.

### Phase7 — Final hardening and production readiness (P2/P3)
Reproducible pinned build/SBOM; browser assets local; clean-install wheel test; secrets/advisories scan against actual release image; nonprivileged deployment, audit log retention, tested backup/restore; current unrooted ordinary-app Android validation for platform claims, separate rooted diagnostics [C/D]. Retest all evidence and document unsupported iOS/device behaviors.

**Gate:** checklist below complete or explicitly waived with owner, scope and risk. No unqualified “enterprise autonomous pentest” or MASVS compliance score from heuristics.

## Top10 highest-value improvements
1. Eliminate dynamic JavaScript event injection; add browser security regression corpus.
2. Fix dashboard initialization and delete all fabricated evidence/metrics/success messages.
3. Enforce offline-first, secret-free provider egress with visible effective config.
4. Require explicit device/package/action scope and stop automatic consent/cross-app crawling.
5. Persist scan-scoped triage and version all exports/evidence.
6. Preserve raw/suppressed candidates and replace unsafe sanitization confidence shortcuts.
7. Isolate parsers/jobs and implement budgets, cancel and restart recovery.
8. Bundle/lock assets and dependencies; add CSP and complete release inventory.
9. Build a responsive accessible design system with real error/empty/partial/offline states.
10. Make the entire approved workflow UI-driven: readiness → scope → scan → evidence → durable triage → redacted export → retention.

## Final production checklist

### Evidence and correctness
- [ ] P01: empty/populated/error dashboards render exact data, no stale selector exceptions.
- [ ] No generated/template text is labeled captured/verified/observed.
- [ ] Every finding has source/rule/version/artifact hash and confidence limitations.
- [ ] Rule ID and scan-scoped finding instance ID are distinct; triage survives restart.
- [ ] All exported formats agree on status, evidence version, partial coverage and scope.
- [ ] Missing tools/providers/permissions yield skipped/error/inconclusive, not secure/clean.

### Authorization, networking and privacy
- [ ] Anonymous and invalid bearer API/WS requests denied; origin/host negative controls retained.
- [ ] Untrusted finding/route/device strings never execute in browser or shell templates.
- [ ] Token not placed in URLs/logs/storage; session revoke/expiry if shared mode supported.
- [ ] Nonloopback deployment has enforced secure transport and documented identity boundaries.
- [ ] Device/package/origin/action scopes checked by backend at execution, not hidden in UI.
- [ ] HTTP redirects/DNS/private-address controls and body/response limits regression-tested.
- [ ] No raw candidate secrets in provider requests; offline enforced and visible.
- [ ] Logs/screenshots/memory captures use synthetic accounts and privacy/retention controls.
- [ ] File modes, backup handling, deletion and redacted exports verified.

### Jobs and release supply chain
- [ ] Hostile parsers isolated/nonprivileged with CPU/memory/time/disk/PID budgets.
- [ ] Concurrent upload/spool/output quota reservation, cancellation and crash cleanup tested.
- [ ] Jobs/telemetry are scan/device-linked, bounded and resumable; side effects not retried blindly.
- [ ] Production dependency/asset/image versions locked; SBOM/advisory scope documented.
- [ ] Package installs/runs from clean wheel; optional tools absent produce actionable readiness.
- [ ] CI includes119 existing tests plus new browser/persistence/egress/scope regressions.
- [ ] Device claims record APK hash, app version, OS build, privilege mode and controls; no root/shell proof presented as ordinary-app exploitation.

### Product and accessibility
- [ ] UI supports APK and IPA only where actual analyzer/device capabilities permit.
- [ ] No-op/unsupported controls disabled with reason; effective settings match next job.
- [ ]401/403/timeout/429/offline/partial/empty/retry states designed and tested.
- [ ] Desktop/narrow/zoom layouts retain actions and target context.
- [ ] Labels, keyboard focus, dialog behavior, status announcements and reduced motion verified.
- [ ] Contrast/touch-target exceptions evaluated on actual rendered states.
- [ ] User can complete a scoped synthetic review without editing backend files manually.

**Final improved behavior:** an honest local security workbench that treats imported artifacts and generated text as untrusted; shows what was actually measured; obtains and enforces scope; protects evidence and secrets; and makes analysis/validation/export recoverable through clear accessible UI. Multiuser/cloud operation is a separate architecture commitment, not a deployment flag.
