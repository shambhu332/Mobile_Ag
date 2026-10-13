# Mobile security market adaptation roadmap (2026-10-13)

## Purpose and decision

This translates the public market review into a realistic MobileAg product plan.
It is not a promise to reproduce every commercial feature, nor a claim that
MobileAg currently matches a commercial MAST platform. MobileAg's defensible
position is a local-first, scope-aware research workbench with unusually clear
evidence and coverage boundaries. Keep that trust property as a release gate.

Market references informing the plan: [OWASP MASTG](https://mas.owasp.org/MASTG/),
[NowSecure MAST](https://www.nowsecure.com/solutions/by-need/mobile-app-security-testing/),
[Appknox](https://www.appknox.com/), [Ostorlab](https://ostorlab.co/),
[Guardsquare AppSweep](https://www.guardsquare.com/appsweep-mobile-application-security-testing),
[MobSF](https://mobsf.org/), [Bishop Fox mobile assessments](https://bishopfox.com/services/penetration-testing-services/mobile-application-assessment),
[Appdome](https://www.appdome.com/mobile-app-security/), and
[Approov](https://docs.approov.io/introduction/overview/). These links describe
vendor-stated capabilities; they are not independent efficacy ratings.

## Baseline already present in this checkout

Do not rebuild existing capabilities under new labels. README.md and the
contributor roadmap already describe offline APK/IPA triage, evidence-bearing
unverified candidates, reports, explicit device/origin/stage approval,
bounded API replay, local sandboxing, scoped triage, readiness checks, and
synthetic benchmarks. The project also explicitly documents decompiler,
coverage, root/shell, and runtime-proof limitations. Current gaps are chiefly
measured breadth, assurance, evidence ergonomics, and operational product
quality—not a missing “AI pentest” button.

## Implementation status

- **P0.3 started:** generated JSON and Markdown reports now include a
  conservative review-surface ledger with mapped analyzer status, runtime
  state, evidence state, and explicit unmapped surfaces. It only crosswalks
  existing coverage metadata; it does not claim that the surface was tested
  end to end. Manifest authorization, serialization, file/URI grants, and
  storage/backup/logging remain unmapped.
- **P0.1/P0.2:** existing structured analyst-evidence gates and
  location-aware synthetic benchmark support were reviewed and reused; this
  change does not broaden either one or assert independent validation.
- Remaining P0 work and all P1–P3 work are still planned, not implemented.

## Prioritized implementation plan

Priority means sequencing, not severity. Each item needs an issue/design review
before broad implementation. No target access, provider egress, or device use is
authorized by this roadmap.

### P0 — Trustworthy evidence and test quality (next)

1. **Evidence contract audit.** Inventory every finding/report/UI/export path.
   Require stable artifact identity (hash, package/version where available),
   analyzer/tool/backend versions, source location, evidence state, and explicit
   gaps. Keep static candidate, runtime observation, analyst attestation, and
   independent verification distinct. Ensure missing evidence never becomes a
   clean verdict.
2. **Finding instance matching.** Extend benchmark evaluation beyond
   CWE-per-case to normalized source/sink locations and individual flow
   instances. Retain positive and hard-negative fixtures; publish parser
   failures, skipped files, and unsupported constructs. Do not publish a single
   accuracy score without corpus size, provenance, and limitations.
3. **Coverage ledger.** Create one coherent per-surface ledger for manifest/IPC,
   serialization, files/URI grants, storage/logging, WebView/deep links,
   network/API/authentication, crypto/native code, and runtime. States must be
   fail-closed (`not_tested`, `candidate`, `observed`, `attested`,
   `independently_verified`, or justified `not_applicable`) with an evidence
   pointer and gap reason. Reuse existing stage and scan coverage instead of
   duplicating or inferring execution from configuration.
4. **Report review UX.** Make a report easy to validate: source → guard → sink,
   reachability prerequisites, observed impact, artifact/build identity,
   reproduction notes, remediation, and a negative control. Redact secrets by
   default; preserve raw evidence separately only with explicit operator action.

**Acceptance:** synthetic fixtures and negative controls; JSON/Markdown/SARIF
round trips; parser/decompiler failures; tests proving no unsupported result is
reported as a pass. Full tests and focused browser regression. No real app,
account, device, or external service is needed.

### P1 — Mobile analysis depth (after P0)

5. **Framework and binary coverage inventory.** Measure Java/Kotlin, native/JNI,
   Flutter, React Native, hybrid WebView, split APK/AAB, multi-DEX, obfuscation,
   and malformed inputs. For each, record supported behaviors and honest
   unsupported/partial status. Add only bounded analyzers with test fixtures.
6. **Android surface analyzers.** Prioritize effective exported-component and
   permission reasoning, app links/deep links, content-provider roots/grants,
   PendingIntent mutability, WebView origin/bridge flows, backup/log exposure,
   and untrusted deserialization—always linking a controllable entrypoint to a
   sensitive sink before raising confidence. A manifest declaration alone is
   not proof of runtime reachability or exploitability.
7. **Native and dependency inventory.** Add bounded native-library and
   dependency inventory with provenance, parser limitations, and advisory
   freshness. Network advisory lookup must remain an explicit separately
   authorized operation; offline analysis stays offline.
8. **Runtime evidence improvements.** Add safe, read-only, reproducible evidence
   collection only for explicitly approved devices and packages. Preserve
   package/PID attribution and OS/build/ABI identity. Root, shell, hooks, or
   older OS results remain labeled modified-lab observations, not ordinary-app
   proof.

**Acceptance:** separate synthetic or authorized, independently reviewed
corpora; exact positive/negative cases; versioned device/tool provenance;
current unrooted-device tests only when specifically approved. Do not claim
whole-app recall from a focused detector benchmark.

### P2 — Workflow and integrations (only after design review)

9. **Reproducible local CI mode.** Provide a documented, deterministic local
   command/JSON contract suitable for CI, preserving offline defaults, stable
   exit semantics, artifact hashes, tool versions, and coverage gaps.
10. **Finding lifecycle and retest.** Add revision-bound triage, fix state, and
    explicit retest linkage to immutable scan identity. Avoid a “fixed” state
    inferred from a later scan unless the same rule/location and relevant
    evidence are compared.
11. **Optional import/export interop.** Consider MobSF/SARIF imports only after
    defining source provenance, schema validation, size/resource limits,
    secret redaction, deduplication, and trust labels. Imported tool results
    must not become MobileAg-verified findings.
12. **Human-assisted testing workflow.** Add a structured test-plan and
    evidence-capture workflow (roles, flows, test accounts, coverage, findings,
    retest), not automated arbitrary tapping or unbounded fuzzing. Scope and
    approval remain explicit.

**Acceptance:** local synthetic integration; exact schemas and migration tests;
negative tests for scope expansion, unsafe imports, stale revisions, and
secret persistence. No vendor API credentials or customer APKs in tests.

### P3 — Optional protection and enterprise features (separate product decision)

13. **Do not build app shielding/RASP or MTD into MobileAg by default.** Those
    are separate product categories with signing, compatibility, SDK, runtime,
    privacy, threat telemetry, and operational-response obligations. If ever
    pursued, first produce a threat model, customer need, platform design,
    privacy review, supply-chain review, and dedicated release/test plan.
14. **Do not add cloud AI as a default scanner dependency.** Existing consented
    aggregate-metadata review must remain optional and isolated. Any new provider
    needs explicit egress/retention review, data minimization, cancellation,
    and fail-closed behavior.
15. **No multi-tenant/remote-hosting claim yet.** The current documented
    single-operator local model is not a SaaS authorization boundary. Remote
    deployment requires a separate architecture for tenant isolation, RBAC,
    secrets, quotas, auditability, upload isolation, and threat modeling.

## Explicit non-goals

- Do not copy claims such as “detects every bug,” vendor accuracy percentages,
  “certified secure,” or a generic vulnerability-count leaderboard.
- Do not equate shielding, pinning, app attestation, obfuscation, or rooted-lab
  behavior with secure backend authorization.
- Do not add automatic target discovery, unapproved live API testing, implicit
  device selection, credential collection, root/SSL bypass, destructive tests,
  or hidden provider/network calls.
- Do not treat MASVS mapping as certification or exhaustive coverage.

## Release scorecard

Every release candidate should report: tests run; benchmark corpus and
partition; TP/FP/FN by detector and backend; instance/location matching status;
parser/decompiler failures; unsupported formats; coverage gaps; tool/build
versions; and any device/browser acceptance performed. Unit tests, synthetic
benchmarks, browser tests, and real-device validation are separate evidence
classes. Passing one does not imply the others ran.

## Suggested sequence

Start with P0.1–P0.3 as separate reviewable changes; they improve trust across
all existing analyzers and reports. Then implement one P1 analyzer at a time,
selected by a labeled corpus and user value. P2 integrations and P3 product
categories need explicit design approval because they materially expand data,
authorization, or operational boundaries.
