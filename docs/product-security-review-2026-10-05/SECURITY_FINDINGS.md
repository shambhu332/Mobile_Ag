# Security and safety findings — current baseline

Ratings are contextual qualitative judgements for a local single-operator security tool, **not CVSS scores or bounty eligibility**. No P0 credential compromise or unauthenticated takeover was demonstrated. P1 items are release blockers for hostile-sample workflows. “Confirmed” below always states the tested boundary. A mocked provider/device establishes the code's behavior, not actual provider disclosure/device exploitation.

## S01 — Stored finding content becomes executable JavaScript when copied
**Severity:** High. **Classification/confidence:** confirmed browser XSS at analyzer-source → saved finding → API → browser boundary; high confidence. Full APK compilation/decompilation/production filter retention not reproduced.

**CWE / OWASP:** CWE-79, output-context injection.

**Affected component / evidence:** `mobileag/analysis/secret_scanner.py:119-138`; `mobileag/web/templates/index.html:1732,1748,1777,1811` (especially Copy Code at1811); additional `executeAdbFromPoc` handler at1751. `evidence/synthetic-finding.json`, `browser-results.json.xss`, `local_probe.py`, `browser_probe.py`.

**Root cause:** untrusted snippets/guides/scripts are concatenated into quoted JavaScript within `onclick`. `encodeURIComponent` leaves apostrophes and arithmetic/function-call characters intact. HTML escaping also does not safely encode a JavaScript string after HTML entity decoding. Some metadata fields are inserted raw into `innerHTML`; those are additional review sinks, not independently proved sample paths.

**Why it matters / attack scenario:** a sample author places a harmless-looking string alongside a matched crypto expression. The actual SecretScanner copies the line into `code_snippet`. If that finding reaches saved results, an authenticated analyst opens it and clicks Copy Code; the browser evaluates a function call embedded in the string, rather than just copying text.

**Demonstrated security impact:** Chromium executed the synthetic marker (count1 in the corrected captured run; benign control0), then read `/api/status` with HTTP200 using the page's authenticated fetch wrapper. The finding remained `UNVERIFIED`; no confirmed finding status or privileged OS test was needed. No credential exfiltration, device operation or host command was performed. Inference: malicious code in this origin could exercise the operator's available APIs, including allowed-device functions; exact device/URL server scopes still apply.

**Recommended fix:** remove all dynamic inline event attributes. Build buttons with DOM APIs, use `textContent` for content, and `addEventListener('click', () => copySnippetValue(value))` with values held as data, never code. Audit finding/API/device/graph sinks; validate classification fields but do not rely on validation alone. Add a CSP without unsafe-inline after removing inline script requirements; bundle scripts.

**UI/UX mitigation:** temporarily remove copy/execute actions for untrusted findings until fixed; label evidence as untrusted. This is only temporary risk reduction. **This cannot be securely fixed through UI/UX alone.** The minimum change is context-safe frontend code; backend auth cannot protect against its own authenticated compromised page.

**Backend requirement:** preserve scope gates; add response hardening and capability separation where appropriate. Do not store samples as pretrusted HTML.

**Verification / regression:** create a real detector finding from a synthetic source containing quote/operator characters, persist it, load through authenticated API, click every action, and assert no script marker/request executes. Cover apostrophes in ordinary Kotlin/JS strings too; ensure copied bytes exactly match input. Add a subsequent compiled synthetic APK test covering decompiler and default filter retention.

**Priority:** P1. **Exploitability:** sample control + retained finding + analyst click. **User/business impact:** analyst session misuse and report compromise. **Difficulty:** medium (systematic renderer refactor).

## S02 — Candidate credentials are sent unredacted to configured LLM providers
**Severity:** Medium, conditional on online mode and configured provider. **Classification/confidence:** confirmed data-flow defect with mocked router transport; high confidence in code path, no real external disclosure tested.

**CWE / OWASP:** CWE-201 (sensitive data in sent data); data minimization/privacy.

**Affected component / evidence:** `analysis/secret_scanner.py:149-159`, `llm/router.py:105-168`, `config/settings.py:38`; `local-results.json.privacy`. Other contextual filters also transmit source context when enabled.

**Root cause:** `_mask_secret` protects log messages and final findings are redacted, but `user_prompt` embeds `item['val']` verbatim. Provider fallback may send the same candidate to more than one configured provider. `offline` defaults false in Settings, although the supplied environment example enables it. GET settings does not initially expose effective offline state.

**Why it matters / attack scenario:** an analyst scanning a confidential client APK with online analysis enabled may disclose an embedded credential to a third-party provider despite seeing redacted evidence afterward. This is a privacy/trust-boundary issue, not a claim all intentional cloud analysis is unauthorized.

**Security impact:** synthetic secret-like value reached a mocked provider call exactly once. No production secret was used. Potential exposure includes usable credentials and proprietary source; actual impact depends on scope/consent and provider retention contracts.

**Recommended fix:** local secret validation first; send only type, length and nonreversible structural features, never the raw candidate. Apply centrally tested egress redaction before every provider call, an explicit per-project provider allowlist, and per-scan consent/config snapshots. Keep offline enforced server-side and make it the safe default.

**UI/UX mitigation:** visible Offline/Cloud badge; list providers and data categories before scan; show a redacted prompt preview. **This cannot be securely fixed through UI/UX alone.** Minimum backend change: remove raw candidate from prompts and enforce egress policy independently of UI controls.

**Backend requirement:** egress policy in router/provider boundary; avoid falling back outside approved processors. Rotate a real exposed credential only if disclosure is confirmed; no rotation claim is warranted for dummy test values here.

**Verification / regression:** sentinel credential tests at all provider adapters, fallback/consensus included; no sentinel bytes cross mocked transport; offline creates zero provider/OSV calls. UI effective config must match worker snapshot.

**Priority:** P1 before confidential online scans. **Exploitability:** online operator workflow, not unauthenticated attacker. **User/business impact:** client secrecy and disclosure obligations. **Difficulty:** medium.

## S03 — UI crawler ignores intended application and automatically accepts consent
**Severity:** Medium. **Classification/confidence:** confirmed safety/scope defect with synthetic UI hierarchy and mocked ADB; high confidence, no real device impact demonstrated.

**CWE / OWASP:** CWE-840 business/workflow logic (scope enforcement); not a claim of Android permission bypass.

**Affected component / evidence:** `dast/ui_crawler.py:22-27,54-91,105-115,153-200`; `web/app.py:1178-1181`; `analysis-results.json.crawler`.

**Root cause:** `package_name` is reported but does not constrain current foreground nodes. Parsed elements discard the package attribute. Labels such as Allow/Agree/Continue are automatically tapped; generic Submit/Login actions are also executed. Device serial authorization is not target-application authorization.

**Attack/user-error scenario:** operator scopes an app on a permitted device; a different app or a system consent dialog is foreground. Crawling operates on that screen and still reports the intended package. A malicious sample could also redirect the foreground; this redirect chain was not tested.

**Security impact:** a hierarchy explicitly belonging to `org.example.unrelated` generated an ADB tap while the result reported `org.example.intended`. Mocked commands only. Real implications include granting consent, changing unrelated state or submitting forms. Arbitrary ADB is already intentionally permitted to the operator; this is unsafe automation, not escalation over the bearer role.

**Recommended fix:** verify foreground package before each step; maintain allowed system-dialog policy tied to a specific requested action; stop on target transitions. Default to observe-only/dry-run; disallow consent, account creation, purchase and destructive flows without explicit step approval. Cap steps/time and provide cancel.

**UI/UX mitigation:** show target/device and planned action preview; require explicit consent for input/taps. **This cannot be securely fixed through UI/UX alone.** Minimum code requirement: package and action-policy checks in the crawler itself.

**Backend requirement:** validate project/device/package/action scope on every job step, not just syntactic package shape.

**Verification / regression:** unrelated foreground and permission dialogs produce zero taps; explicitly permitted safe navigation works; cancellation halts commands; no real third-party account/device testing needed.

**Priority:** P1 before autonomous device use. **Exploitability:** operator starts crawler with wrong/changed foreground. **User/business impact:** out-of-scope or unintended actions. **Difficulty:** medium/high.

## S04 — Triage is neither durable nor scoped to a scan
**Severity:** Medium. **Classification/confidence:** confirmed integrity/reliability defect, high confidence; not cross-tenant BOLA.

**CWE / OWASP:** CWE-840 workflow integrity; incorrect object identity.

**Affected component / evidence:** `web/app.py:592-619`, `analysis/ios_analyzer.py:113,141,177` (fixed rule IDs); `local-results.json.persisted_feedback`, `.unknown_feedback`; `analysis-results.json.cross_scan_triage`.

**Root cause:** endpoint accepts finding ID without scan ID, updates all matching in-memory scans, never updates persisted dashboards/reports, and returns success even when no finding exists. iOS rules use stable IDs such as `ios-ats-001` across scans.

**Attack/user-error scenario:** analyst triages an old persisted scan and trusts the success toast, or triages one of two iOS scans containing the same rule ID. The saved record is unchanged or both scans' findings change.

**Security impact:** HTTP200 after confirmation followed immediately by GET still returned UNVERIFIED for a disk-backed fixture. Unknown finding ID also returned success. Two active fixtures with the same actual iOS rule ID both changed to FALSE_POSITIVE from one request. Evidence/export integrity, not account takeover, is demonstrated.

**Recommended fix:** canonical durable record keyed by `(project_id, scan_id, finding_instance_id)`; separate rule ID from instance ID; validate existence, perform transactional revision-checked updates, append actor/time/evidence log, regenerate/version exports consistently. Whitespace-only confirmation notes should not satisfy evidence validation.

**UI/UX mitigation:** pending/saved/failed states with durable version and unsaved warning. **This cannot be securely fixed through UI/UX alone.** Minimum backend requirement: scoped identity, persistence and proper404/409 responses.

**Verification / regression:** POST→GET→restart→GET→SARIF roundtrip; duplicate rule IDs across scans isolated; unknown404; concurrent edits409; immutable evidence history.

**Priority:** P2, before using outputs as authoritative deliverables. **Exploitability:** normal analyst actions; no attacker needed. **User/business impact:** lost or misattributed security decisions. **Difficulty:** medium.

## S05 — Irrelevant comments suppress a finding through the sanitizer filter
**Severity:** Medium (analysis integrity). **Classification/confidence:** confirmed synthetic-source filter bypass, high confidence; not proof of a vulnerability in the analyzed crypto use.

**CWE / OWASP:** CWE-184 incomplete validation logic; security-analysis quality.

**Affected component / evidence:** `filters/sanitizer_check.py:13-43,91-107,146-165`; `filters/pipeline.py:155-188`; `filters/confidence.py`; `analysis-results.json.baseline` and `.irrelevant_comment`.

**Root cause:** generic substrings including `?`, `Base64.encode` and `SecureRandom` anywhere in nearby text count as sanitization, without comment removal, CWE-specific semantics or data/control-flow relation. Three matches yield0.2 and bypass contextual analysis. The aggregate score hides candidates below0.6 from final findings; neutral scores for unavailable controls are treated as measured evidence.

**Attack scenario:** a sample author adds irrelevant words/comments around the same analyzer match. With offline/default filtering and six reference files, the unmodified candidate was retained (0.643); adding a comment dropped it (0.522). Detector raw count stayed1 in both cases. Source boundary confirmed; comment survival through APK decompilation is not claimed.

**Security impact:** false-negative/finding suppression at source analysis boundary; no runtime app exploit demonstrated. Also review manifest entrypoint reachability: Java reference counts alone do not establish Android lifecycle reachability.

**Recommended fix:** use CWE-specific control-flow-aware checks; strip comments before lexical heuristics; model unknown/skipped/error separately from safe. Preserve all candidates with review/suppression reasons instead of silently eliminating them. Severity is not a calibrated confidence feature.

**UI/UX mitigation:** show raw/retained/suppressed candidates and coverage; never equate zero results with secure. **This cannot be securely fixed through UI/UX alone.** Minimum code change: no security suppression from generic unrelated substrings and explicit unknown states.

**Backend requirement:** durable rule decision provenance, raw candidate retention and semantically grounded filter contracts.

**Verification / regression:** adding comments/irrelevant safe calls cannot change reachability/sanitization; real protective control on all paths changes only the relevant rule; test exported entrypoints and offline/missing-model behavior.

**Priority:** P2. **Exploitability:** source control or naturally occurring irrelevant text. **User/business impact:** missed investigation leads. **Difficulty:** high for full semantics; low/medium to stop unsafe suppression now.

## S06 — Mutable remote scripts execute with full dashboard trust
**Severity:** Medium, hardening risk; **not a confirmed CDN compromise**. **Confidence:** high static/runtime observation.

**CWE / OWASP:** CWE-829 inclusion from untrusted control sphere; defense-in-depth CSP.

**Affected component / evidence:** `web/templates/index.html:9,36-42`; `web/app.py:476-481`; browser request/library inventory; local response headers contain no CSP.

**Root cause / why it matters:** unversioned Tailwind, vis-network, Chart.js and `lucide@latest` scripts have no SRI. Inline code/handlers require broad script execution. These third parties execute in the same origin as the operator token and authenticated APIs. CDN availability is also a product dependency even when analysis offline mode is enabled.

**Attack scenario / security impact:** hypothetical compromised CDN/package can access dashboard state or make operator requests. No third-party compromise or exploitation was attempted. OSV package absence is not assurance for mutable browser assets.

**Recommended fix:** vendor/build exact reviewed versions and bundled CSS, lock integrity hashes, remove runtime CDN and unused dependencies, apply nonce/hash-based CSP and frame-ancestors, no-store on sensitive responses, nosniff and conservative Referrer-Policy. CSP supplements safe DOM construction, not replaces it. See [OWASP CSP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).

**UI/UX mitigation:** complete offline shell, honest unavailable module states. **This cannot be securely fixed through UI/UX alone.** Build/deployment changes are required.

**Backend requirement:** response headers and asset policy; integrate reproducible release SBOM.

**Verification / regression:** block all external network in browser and exercise every view; assert no remote script requests, no CSP violations and no dynamic inline handlers; verify asset hashes in CI.

**Priority:** P2, alongside S01. **Exploitability:** upstream compromise prerequisite. **User/business impact:** broad operator trust and offline outages. **Difficulty:** medium. **Change class:** C/D.

## S07 — Heavy analysis is insufficiently isolated from the web process and host
**Severity:** Medium hardening/reliability risk; resource exhaustion exploit **not demonstrated**. **Confidence:** high architectural observation, workload impact unmeasured.

**CWE / OWASP:** CWE-400 / API resource-consumption hardening.

**Affected component / evidence:** `ingestion/apk_extractor.py:49-84`; `web/app.py:1224-1228,1449-1478,1491-1561`; `dast/adb_manager.py:36-63`; `filters/reachability.py:72-104`.

**Root cause:** parsers run as local operator without per-job sandbox/CPU/memory/output limits; tool timeouts and ZIP bounds help but do not contain parser vulnerabilities or output amplification. Synchronous taint/disk reads run on API event loop. Upload quota excludes multipart spool/extracted reports and is not an atomic reserved quota. Scan/fuzz admission limits do not bound every direct DAST endpoint; crawl steps and log lines lack range limits. Sequential WS broadcast may accumulate two seconds per slow subscriber.

**Attack scenario / impact:** operator imports a pathological sample or concurrently submits expensive allowed tasks; potential UI hangs, disk growth or privileged parser exposure. No stress test, archive bomb, parser exploit or host takeover was performed. Max input size and two scan slots materially reduce risk; they are not absent controls.

**Recommended fix:** isolated worker process/container with read-only sample mount, private output, deny-network default, nonprivileged identity, CPU/RAM/PID/wall-time/output limits; durable queue, global/device concurrency and cancellation. Atomic quota reservations including spool/expanded bytes; bounded per-subscriber buffers and concurrent dispatch.

**UI/UX mitigation:** queue/progress/cancel/storage meter. **This cannot be securely fixed through UI/UX alone.** Minimum backend/infrastructure change: process isolation and server-enforced job/resource budgets.

**Verification / regression:** bounded benign large fixtures, cancellation mid-parser, interrupted worker recovery, aggregate quota race, slow WebSocket subscriber; measure event-loop latency without overwhelming a live machine.

**Priority:** P2 before hostile production samples. **Exploitability:** authenticated workflow/sample author prerequisites. **User/business impact:** availability and workstation blast radius. **Difficulty:** high.

## S08 — Evidence lifecycle needs explicit privacy and retention controls
**Severity:** Low, privacy hardening. **Classification/confidence:** static-confirmed capabilities; no unauthorized disclosure demonstrated.

**CWE / OWASP:** CWE-200/922 risk areas, not established exploitable instances.

**Affected component / evidence:** `web/app.py:1113-1122,1133-1140,1449-1478`; `reporting/report_engine.py:39-65`; `security/privacy.py`; `dast/mitm_proxy.py:33-40`.

**Root cause / data flow:** uploads/extracted files contain target secrets by nature, written using normal process umask. Reports redact known patterns, not arbitrary PII/credentials; logcat returns raw lines and screenshots contain whole screen. No in-app artifact deletion/retention/quota-recovery workflow. Redacted JSON is not equivalent to sanitized raw artifacts.

**Scenario / impact:** a shared workstation account, overly broad filesystem permissions, backups or exported evidence could disclose target data. No world-readable deployment was proven. Bearer-authorized analyst access to logs is expected functionality, not itself a vulnerability.

**Recommended fix:** private data directories and explicit file modes, encryption-at-rest according to deployment threat model, redacted views by default, deliberate raw-evidence reveal/export, retention/deletion policy and backups policy. Never promise SSD secure erase; use cryptographic disposal where supported. Extend structured redaction without corrupting evidence; preserve raw encrypted source under restricted access.

**UI/UX mitigation:** per-project retention, storage usage, delete confirmation and export redaction preview. **This cannot be securely fixed through UI/UX alone.** Minimum change: filesystem/storage policy, backend deletion and redaction enforcement.

**Backend requirement:** auditable artifact ownership/lifecycle, no-store headers and enforced retention tasks.

**Verification / regression:** synthetic credential/PII fixtures across reports/WS/logs/exports; inspect file modes on fresh data root; delete preserves unrelated files and handles backups policy; unauthorized requests remain401.

**Priority:** P2. **Exploitability:** secondary local/export exposure. **User/business impact:** target confidentiality. **Difficulty:** medium.

## S09 — Malformed traffic objects cross validation and produce HTTP500
**Severity:** Low. **Classification/confidence:** confirmed API validation/reliability defect, high confidence.

**CWE / OWASP:** CWE-20 input validation.

**Affected component / evidence:** `web/app.py:999-1000,1200-1219`; `dast/traffic_auditor.py`; `analysis-results.json.traffic_malformed`.

**Root cause:** `transactions: list[dict[str, Any]]` validates only outer shape; code builds a plain HTTPTransaction and heuristics assume string URLs/header maps. A valid outer JSON body with integer URL/list headers produces500 rather than422.

**Scenario / impact:** malformed captured traffic or operator import breaks analysis; generic500 was observed, not stack-trace or secret leakage in the response. No persistent process crash demonstrated.

**Recommended fix:** nested Pydantic transaction model with bounded strings/lists, header types, valid status range and method enum; deterministic per-record partial errors where appropriate. Review neighboring unbounded request collections and unknown Frida script fallback too.

**UI/UX mitigation:** field-specific errors and import preview. **This cannot be securely fixed through UI/UX alone.** Minimum backend change: validate nested structures before constructing domain objects.

**Backend requirement:** safe structured400/422 errors, request correlation ID; redacted operator diagnostics, no raw exception internals.

**Verification / regression:** integer/null URL, list/null headers, oversized capture list, malformed JSON and boundary status values; invalid inputs422 not500; valid captures unchanged.

**Priority:** P2. **Exploitability:** authenticated malformed request. **User/business impact:** broken workflow, low security impact. **Difficulty:** low.

## S10 — Remote deployment and token lifecycle are not production identity controls
**Severity:** Medium hardening **for remote/shared deployment**, informational under intended local isolated use. **Confidence:** high static observation; no live token exposure tested.

**CWE / OWASP:** CWE-319 risk if nonloopback plaintext used; authentication lifecycle hardening.

**Affected component / evidence:** `web/app.py:90,1627-1644`; `web/security.py:21-53`; `web/templates/index.html:1216-1231,2385-2420`.

**Root cause:** one process-wide bearer authorizes everything, no expiry/revocation/logout/account isolation. Server binds loopback by default (good). Remote bind requires configured token and allowed host but plain uvicorn HTTP is still possible, with no required TLS terminator. A token is not user identity; rotating process token is not per-session logout. Query-parameter tokens/localStorage are not used (good).

**Scenario / impact:** operator intentionally exposes dashboard on shared network without TLS, or shares a token between users; sniffing/replay or indistinguishable actions become possible. Not a default remote authentication bypass. Strong random default token makes brute force impractical; no missing password/MFA bug is claimed in a product without accounts.

**Recommended fix:** formally support loopback-only mode now; require TLS-bound trusted reverse proxy or local tunnel for remote mode. For shared use, introduce identity, revocable scoped sessions, roles and object ownership, action audit log, and per-project device/URL scopes. Explicitly reject unsupported deployment modes.

**UI/UX mitigation:** structured connection screen, session-expired/reconnect states, logout/revoke action when implemented, clear privileged-mode badge. **This cannot be securely fixed through UI/UX alone.** Minimum technical change: secure transport policy and server session lifecycle, not a hidden button.

**Backend requirement:** distinguish trusted proxy headers, TLS enforcement, session revocation and authorization on every route before multiuser rollout.

**Verification / regression:** remote plaintext startup rejected or documented tunnel enforcement; expiry/revocation closes API/WS; two identities cannot access each other's scan/device if multiuser mode is added.

**Priority:** P2; prerequisite for remote/shared release. **Exploitability:** unsafe deployment/token sharing. **User/business impact:** broad operator capability misuse. **Difficulty:** low for loopback restriction; high for actual multi-tenancy.

## Leads and non-findings (do not report as confirmed exploits)
- `filters/sanitizer_check.py:124-139` accepts an existing absolute file path before resolving beneath source root. Synthetic helper call read an out-of-root synthetic file; **attacker control of that argument through a deployed route was not established**. Constrain to analysis root defensively; investigate provenance before claiming arbitrary file read/exfiltration.
- WebSocket subscriber cap check precedes auth wait and is not atomic; global broadcasts are not tenant isolation. No flooding test performed. Per-job subscription is an integrity/reliability recommendation for current single-operator mode.
- DAST background optional `apk_path` install lacks the dedicated install route's upload-root check (`web/app.py:1310-1317`). Bearer operator already has arbitrary scoped-device shell: this is an invariant gap, not proved host-read escalation. Reuse validated upload handles.
- Automatic detectors still map benign patterns to strong titles/severities: e.g. `analysis/api_mapper.py:103-115` calls an admin path reference HIGH; `code_reviewer.py:64-71` matches an `openFile` signature without a complete traversal trace. Candidate status helps but these need rule-level semantics, not vulnerability claims.
- No confirmed current upload traversal, unrestricted replay SSRF, host command injection, unauthenticated device control, mobile ordinary-app exploit or exploitable dependency advisory was found in this review. This is not a guarantee none exist.
