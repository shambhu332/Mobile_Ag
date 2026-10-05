# MobileAg — current-code security and product review

> **Subsequent implementation update:** the findings below describe baseline `56d2feb`. Worktree fixes and fresh validation are recorded in [FIX_STATUS.md](FIX_STATUS.md). Do not treat old reproduction scripts or this baseline readiness assessment as evidence of current behavior.

**Reviewed baseline:** `56d2febcb204e2a156d61677eac6197ea2543bd0` (main),2026-10-05. This is a new **post-fix** review, not a reissue of the older `docs/audit-2026-10-05/REVIEW.md`. Production source was not changed during this review. Findings are not marked fixed merely because recommendations or probe scripts exist.

## Executive summary

**Not ready for hostile-sample production use or remote/shared deployment.** The prior server-side improvements are meaningful: local tests returned401 for anonymous APIs,403 for foreign origin/unscoped devices/unlisted replay destinations, and200 for valid operator access. The existing suite passes **119 tests,1 dependency deprecation warning,36.17s**.

Nevertheless, actual browser/workflow testing found release-blocking defects that those tests miss:
- **Stored finding XSS:** clicking Copy Code on a synthetic finding emitted by the real analyzer executed a harmless marker and made an authenticated status request. Full APK/decompiler/default-filter end-to-end retention was not tested.
- **Dashboard initialization crashes** at an absent DOM element, leaving hardcoded21 findings/78% MASVS/94.2% consensus on screen instead of actual data.
- **Evidence and execution claims are still fabricated in parts of the product:** a static unverified finding gets VERIFIED/SINK_REACHED text, Copilot returns canned observed exploits, and agent run buttons send no job request.
- **Confidential-data and device-safety boundaries remain incomplete:** raw candidate secrets reach the provider-call boundary; the crawler acts on an unrelated package's synthetic foreground hierarchy.
- **Triage is unreliable:** disk-backed feedback reports success but is not saved; duplicate iOS rule IDs update multiple scans. Irrelevant comments can also suppress a static candidate.

No real user credentials, target accounts, devices or production APIs were used. Mocked provider/device behavior is not claimed as live compromise. No confirmed P0 finding, current unauthenticated takeover, bounty eligibility or numeric vulnerability-severity score is asserted.

## Deliverables / reading order
1. [Attack-surface and data-flow map](ATTACK_SURFACE.md)
2. [Complete security/safety findings](SECURITY_FINDINGS.md)
3. [All37 explicit routes: API matrix, inputs, policies and regression tests](API_MATRIX.md)
4. [Top10 UX issues, screen-by-screen review, state matrix and redesigned flow](UI_UX_REVIEW.md)
5. [Architecture, privacy/dependency review, seven-phase roadmap and release checklist](ARCHITECTURE_AND_ROADMAP.md)
6. [Reproduction instructions and evidence limitations](evidence/README.md)

## Top10 security-risk priorities

This table deliberately includes **labeled hardening/quality risks**, rather than inventing ten exploitable vulnerabilities. Severity describes this local-tool threat model; priority is remediation order. P0 immediate=critical compromise; P1 urgent=high-impact/release-blocking; P2 important=medium/security/quality; P3 improvement=polish.

| Rank | Finding | Classification | Severity | Priority | Fix class |
|---|---|---|---|---|---|
|1|S01 Untrusted finding → inline JavaScript handler|Confirmed browser XSS at source/finding boundary|High|P1|C frontend, D defense-in-depth|
|2|S02 Raw secret candidate → LLM provider prompt|Confirmed mock-transport privacy defect; online prerequisite|Medium|P1 before confidential online use|B/C plus A consent|
|3|S03 Crawler ignores intended app/accepts consent|Confirmed synthetic/mock execution-scope defect|Medium|P1 before autonomous DAST|B/C plus A review|
|4|S04 Lost/cross-scan triage|Confirmed report-integrity defect, not cross-tenant BOLA|Medium|P2|B/C|
|5|S05 Comment-driven sanitizer suppression|Confirmed source-level analysis-integrity defect|Medium|P2|C plus A visibility|
|6|S06 Mutable CDN scripts/full browser trust|Hardening; no CDN compromise shown|Medium|P2|C/D|
|7|S07 Parser/job resource isolation|Hardening/reliability; no exhaustion/RCE demonstrated|Medium|P2|B/C/D|
|8|S10 Remote transport/session architecture|Conditional hardening, local default is loopback|Medium remote; informational local|P2 before remote/shared release|B/D|
|9|S08 Evidence privacy/retention|Hardening; no unauthorized reader established|Low|P2|A/B/C/D|
|10|S09 Nested capture input produces500|Confirmed validation/reliability defect|Low|P2|B/C|

**Separate product release blockers:** P01 dashboard crash and P02 fabricated evidence/no-op actions are High product-impact defects, not ten additional security exploits. All ten UX problems and all ten highest-value improvements are in the linked UI review and roadmap.

## Domain assessment (0–10)

These are **reviewer maturity/readiness assessments requested for planning**, not CVSS, vulnerability severity, percent secure, certification or statistically calibrated risk. Higher=better:0 absent/unusable,2 major blockers,4 substantial incomplete controls,6 baseline controls with significant gaps,8 verified release controls,10 sustained independently validated operation. Unknown/unexercised areas reduce confidence; no false precision is intended.

| Domain | Readiness | Evidence / reasoning |
|---|---:|---|
|Mobile application security|N/A|No shipped native Android/iOS application to certify. Tooling coverage is assessed below; no current real-device proof|
|Mobile-analysis tooling coverage|4|Static Android/iOS/smali/native heuristics exist; source suppression/evidence claims and ordinary-app validation remain unresolved|
|API security|5|Auth/scope/archive/replay controls and tests exist; unsafe browser consumes privileged API, nested input/persistence/job gaps|
|Authentication|6 in local mode|Strong process bearer and WS auth; no lifecycle/identity model; token prompt recovery incomplete; remote use not mature|
|Authorization|5 in local mode|Exact serial/origin boundaries work; intended app/action policy missing in crawler; no tenant isolation promised|
|Data protection|4|Known-pattern redaction and scoped access, but raw artifacts/outputs/egress and retention need enforcement|
|Privacy|3|Cloud candidate-secret transmission and incomplete effective privacy UI; synthetic mock proof, not a real leak|
|Business logic|3|Triage identity/persistence, fake run/evidence semantics and unsafe automation; payments/accounts absent|
|Architecture|4|Clear analysis modules but monolithic web/client, global state and in-process non-durable jobs|
|Performance|4, low confidence|Several bounds/thread offloads exist; full-history reads/synchronous analysis/unbounded client feed; no load benchmark|
|Reliability|3|119 tests pass, yet boot render, durable triage, malformed capture and failure-state defects reproduced|
|UI/UX|2|Critical dashboard/provenance defects, dead controls and poor recovery despite broad feature inventory|
|Accessibility|2, partial assessment|Explicit label/dialog/live-region gaps and narrow-screen clipping; no full screen-reader audit|
|Production readiness overall|2|Do not release hostile-sample/remote workbench until P1 gates and persistence/privacy/worker controls pass|

No native-app MASVS or target-API assurance score is derivable from this tooling repository. [OWASP MASVS/MASTG](https://mas.owasp.org/MASVS/) supplies verification controls and testing guidance, not evidence that this tool's percentage badges are valid.

## Scope, method and coverage

- Source baseline was clean before audit; SHA256 inventory of109 selected source/template/data/test/build files in `evidence/source-snapshot.json`;77 Python files under `mobileag` inventoried, plus config/tests. The inventory is not a claim every possible path was dynamically executed.
- Attack-surface map and AST inventory of37 explicit route/method pairs/20 request models created before final findings. Framework docs routes noted separately. All current route handlers and shared authorization/input boundaries reviewed; focused source-to-sink validation on hostile content, scopes, reporting, egress and product state.
- Ingestion, analyzers, filters, reporting/generators, LLM routing, knowledge adapters, DAST, CLI/config/packaging examined for entrypoint wiring, trust and coverage. This is a baseline-wide engineering review, not exhaustive formal verification of every analyzer instruction or native third-party tool.
- Browser: real template/scripts in isolated Chromium, eight views, desktop/narrow dimensions, DOM semantics, harmless XSS marker/authenticated GET, fabricated evidence and no-op actions. No authorization hooks changed. Fixture results stored as normal persisted dashboard; only graph/device integrations mocked to prevent real access.
- API: real FastAPI middleware/handlers via local TestClient; synthetic persisted/in-memory scans and malformed inputs; negative auth/origin/device/URL controls.
- Providers: mocked router transport confirmed candidate-secret inclusion; no cloud model prompts sent during tests. Public OSV lookup sent only package names/versions. Browser fetched public library/font assets; no external target testing.
- Device/crawler: synthetic XML + mocked ADB only. No connected device queried or commanded by the audit harness; no Android/iOS OS build or APK hash exists for a target because no target app/device was assessed. Source hashes and browser/host versions replace—not substitute for—future device evidence.
- Host snapshot: Linux7.2.8-2-cachyos x86_64, Python3.14.7; Chromium155.0.8059.12. Clean validation environment package versions saved. System Playwright expected a different cached browser revision, so explicitly selected cached Chromium1247 distribution; actual runtime version recorded.
- Dependency results:108 public Python packages queried; zero OSV matches at recorded time. Container images, CDN versions, SDK/native tools and actual deployment reachability not covered by that result.
- Secret review: known-pattern current tracked-text scan, values not printed; eight demo/test locations. No real credential verification, no exhaustive git-history or high-entropy scan. Do not infer absence of all secrets.

## Validation highlights

| Check | Observed | Meaning / limit |
|---|---|---|
|Full existing suite|119 passed;1 warning|Regression baseline only; missing browser/workflow tests remain|
|Auth/origin/scope controls|401 anonymous;200 valid;403 foreign origin/device/URL|Useful controls confirmed on sampled real routes|
|Copy Code synthetic source finding|Marker executed; authenticated status GET200|S01 browser authority crossing; no device/host exploit performed|
|Dashboard normal fixture|Null `top-obfuscation`; actual1/display21 and78%|P01 reproduced, not simply missing loaded assets|
|Proof pane|UNVERIFIED finding gets VERIFIED/SINK_REACHED|P02 reproduction; no runtime evidence exists|
|Run agent buttons|No requests issued|No actual execution behind actions|
|Persisted feedback|POST200; next GET stillUNVERIFIED|S04 durability defect without restart required|
|Duplicate iOS ID feedback|Both scans becomeFALSE_POSITIVE|S04 wrong-object identity behavior|
|Filter comment change|Raw1 retained1 at0.643 → raw1 retained0 at0.522|S05 source-level suppression; not proof of app exploit|
|Secret prompt|Synthetic candidate present at mocked route call|S02 egress construction confirmed; zero real provider calls|
|Crawler wrong foreground|Unrelated package generates tap mock|S03 logic confirmed; zero real device commands|
|Nested traffic URL/header wrong types|HTTP500|S09 input contract gap; no response stack leak claimed|
|Narrow390px|240px sidebar,150px main,9 offscreen buttons|P05 visual/geometry evidence|

## Working conclusion

Keep this a **local, scoped, supervised research workbench**, not an autonomous vulnerability-proof or compliance system. Fix browser trust and misleading evidence first, enforce cloud/device boundaries next, then make triage/jobs durable and the UI accessible/recoverable. The desired end state is a workflow the analyst can operate through UI safely, while authorization, egress, persistence and execution limits remain server-enforced.
