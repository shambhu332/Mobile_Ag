# Complete current API security inventory

Baseline: `56d2feb`. 37 explicit route/method pairs from `web/app.py`, including `/` and WebSocket; 35 explicit `/api` pairs. No invented target APIs.

**Auth legend:** B = same shared bearer, full trusted-operator authority; W = token in first WebSocket JSON. H/O = allowed Host and same-origin Origin when supplied. All routes have H/O. D = exact device serial allowlist; C = exact connection allowlist; O = exact outbound origin policy. There are no separate users/roles/tenants: scan UUID secrecy is not a substitute for ownership, but lack of per-user ownership is not a BOLA finding in this local single-operator model. Every claimed endpoint defect below requires bearer access unless otherwise stated.

HTTP JSON bodies have a global1MiB ceiling; upload128MiB plus multipart allowance, archive expansion512MiB; see actual constants and middleware. Missing fine-grained list/type limits are distinguished from missing all limits. No GraphQL server, webhooks, reset/login/refresh/payment endpoints exist. `apis/fuzz` is an offline transaction audit, not an autonomous live attack.

| Endpoint | Method | Auth | Authorization | Input Validation | Sensitive Data | Risk / severity | Recommended Fix | Validation/test |
|---|---|---|---|---|---|---|---|---|
| `/ws/telemetry` (147) | WEBSOCKET | W | Operator | Initial JSON token; max 32 authenticated subscribers; five-second auth wait | All scan/device telemetry | Low / P10: global feed, no job subscription; pending-auth cap not atomic | Authenticate before connected UI; bounded per-job feeds, connection admission lock | Wrong token closes1008; parallel auth cap; cross-job isolation |
| `/` (476) | GET | Public shell | H/O only | Host/Origin gates; no bearer needed for shell | No real target data in HTML; session prompt | High S01/P01/P02; Medium S06 | Safe DOM events, no seeded result values, bundle assets/CSP | Boot empty and populated scans; click hostile snippets; offline assets |
| `/api/status` (485) | GET | B | Operator | No input | Provider names, DB URI, counts | Low hardening: infrastructure metadata to trusted operator | Return actual version and capabilities; no secrets | 401 without bearer; fields match deployed config |
| `/api/graph/status` (502) | GET | B | Operator | No input; optional DB connectivity check | DB URI and connectivity | Low operational: per-request dependency probe | Cache readiness briefly; generic diagnostic IDs | DB offline produces clear fallback; timeout |
| `/api/scans` (513) | GET | B | Operator | No pagination; reads up to100 persisted reports plus active | Full findings and target snippets | Medium P08: whole-object list, synchronous disk | Paginated sorted summaries; separate details | Large synthetic history stays bounded; stable newest order |
| `/api/scans/{scan_id}` (522) | GET | B | Operator | Exact ID lookup; not filesystem concatenation | Full scan findings/snippets | S01 downstream rendering; no BOLA under single operator | Typed response and provenance; safe UI; retention | Unknown404; hostile strings inert; partial scan identifiable |
| `/api/scans/{scan_id}/graph` (542) | GET | B | Operator | ID passed as Cypher parameter or embedded lookup | Target topology | Low hardening: graph is inferred, not exploit proof | Label inferred edges and coverage; preserve job ID | Unknown scan; missing DB; edge provenance |
| `/api/scans/{scan_id}/sarif` (565) | GET | B | Operator | Exact ID lookup; generated SARIF | Source paths/snippets | S04 export/triage inconsistency | Export from canonical persisted finding version | Same verdict in JSON/SARIF after restart |
| `/api/scans/{scan_id}/apis` (574) | GET | B | Operator | Exact scan lookup | Discovered target URLs/paths | P09: discovery is not actual server verification | Separate discovered/observed/tested; no implied authorization | Empty routes truthful; no demo fallback |
| `/api/findings/{finding_id}/feedback` (593) | POST | B | Operator | Verdict allowlist; CONFIRMED requires nonempty notes; no scan key | Analyst evidence/decisions | Medium S04 confirmed integrity defect | Durable transaction by scan+finding+revision;404 unknown | Restart roundtrip; duplicate iOS IDs isolated; empty/whitespace notes |
| `/api/copilot` (629) | POST | B | Operator | Typed prompt and optional scan ID; no existence/context check | User prompt; static returned claims | High P02 product-integrity defect, not auth bypass | Disable or clearly label templates; evidence-grounded context | Nonexistent scan rejected; never claim observed results without evidence |
| `/api/agents` (808) | GET | B | Operator | No input; static list | Static invented runtimes/counts | P02: false live capability display | Use run-derived facts or show Not run; disable no-op actions | Run button creates job ID or explicit unavailable state |
| `/api/settings` (895) | GET | B | Operator | No input; runtime dictionary, not complete effective Settings | Nonsecret provider/DB config | Medium P07/S02: offline/effective config missing | Expose resolved nonsecret flags, sources, scope and capability status | UI equals next-run effective config; never returns credentials |
| `/api/settings` (901) | POST | B | Operator | Explicit writable-key allowlist; bool checks; entropy bounds | New-run analysis config | P07: memory-only persistence; no UI offline control | Persist versioned allowed settings; display restart/session scope | Unknown key422; invalid type422; reload/restart expectation |
| `/api/dast/devices` (1030) | GET | B | Operator | Bearer only; enumerates devices; not filtered to scope | Serial/model/OS/root diagnostics | Low hardening/P04: connected is not authorized | Expose separate allowed/connected flags; no auto-selection | Outside allowlist never selectable; zero devices no fake root status |
| `/api/dast/connect` (1054) | POST | B | Operator + C | Exact MOBILEAG_ALLOWED_CONNECT host:port | ADB network address | Expected privileged function; no unrestricted connect confirmed | Keep backend allowlist; scope setup UI | Unknown endpoint403; mocked approved connect |
| `/api/dast/root` (1061) | POST | B | Operator + D | Exact serial allowlist | Root state | Medium P04 operational safety | Require explicit target review and root warning; audit action | No implicit device; verify exit code and shell identity |
| `/api/dast/install` (1068) | POST | B | Operator + D | Serial allowlist; upload-root resolved path; Android archive | Host APK path; device app data | Medium safety: reinstall and auto-grant true | Opt-in permissions/reinstall confirmation; opaque upload ID | Outside path400; invalid archive400; no install on failure |
| `/api/dast/launch` (1083) | POST | B | Operator + D | Serial allowlist; typed component; argument quoting | Component name and device output | Expected scoped operator action | Validate intended package/component and display command preview | Special chars stay arguments; wrong package denied under package policy |
| `/api/dast/deeplink` (1090) | POST | B | Operator + D | Serial allowlist; typed URI | URI tokens; launch output | Medium safety: external handlers; heuristic success | Review URI/handler scope; inspect actual command result | Handler escape requires approval; command failure not success |
| `/api/dast/execute_adb` (1106) | POST | B | Operator + D | Serial allowlist; arbitrary shell intentionally permitted | Shell output; potentially sensitive target data | Powerful intended operator function; amplifies S01, not standalone injection | Separate dangerous capability; preview/reconfirm/log; retain backend scope | Unauth401/unscoped403; failure status surfaced; no command executed by read UI |
| `/api/dast/logcat` (1113) | GET | B | Operator + D | Serial allowlist, optional package syntax, integer lines no explicit bounds | Raw logcat/PII plus redacted findings | Low S08; Medium S07 workload lead | Bound lines; explicit raw-evidence reveal; redact default | Synthetic secrets hidden; negative/huge lines422; command timeout |
| `/api/dast/logcat/clear` (1126) | POST | B | Operator + D | Serial allowlist | Device logs deleted | Medium P04: destructive evidence action | Confirm buffer clear; warn scope and preserve needed evidence | Cancel does not dispatch; reported success follows command |
| `/api/dast/screenshot` (1133) | POST | B | Operator + D | Serial allowlist | Entire device screenshot potentially PII | Low S08 expected sensitive capture | Explicit consent, foreground package check, no-store and retention | No automatic capture; capture failure explicit; synthetic screen only |
| `/api/dast/storage` (1144) | POST | B | Operator + D | Serial allowlist and package syntax | Target private storage diagnostics | Low S08 privileged evidence boundary | Label root/run-as prerequisites; no ordinary-app impact claims | Nonroot permission denial is inconclusive; no secret output by default |
| `/api/dast/providers` (1152) | POST | B | Operator + D | Serial/package syntax; list of authority strings | Provider query outputs | Medium safety: authorities not package-bound | Resolve declared authorities and review scope; bound list | Outside package blocked; SQL error alone not CONFIRMED |
| `/api/dast/deeplinks` (1161) | POST | B | Operator + D | Serial/package syntax; list of URI strings | URI/handler results | Medium safety: redirect outside target app | Bound URIs; package-aware handling and preview | External handler stop; no auth claim from launch success |
| `/api/dast/memory` (1170) | POST | B | Operator + D | Serial/package syntax | Root-access memory evidence | Low S08 privacy; privilege-specific results | Explicit consent; transient handling; privileged-only evidence badge | Unavailable/root denied not clean; synthetic secret masking |
| `/api/dast/crawl` (1178) | POST | B | Operator + D | Serial/package syntax; unbounded max_steps | Foreground UI hierarchy/input | Medium S03 confirmed mock target-scope defect; S07 limits | Check foreground package every step; no automatic consent; cap/timebox | Unrelated foreground => zero taps; permission dialog stops |
| `/api/dast/frida` (1185) | POST | B | Operator + D | Serial/package syntax; unknown script_type falls back to unpinning | Generated hooks and init evidence | Medium operational safety/P04; not persistent exploit proof | Enum script type; show generated script vs actual deployed script; explicit confirmation | Bad type422; correct serial; init failure not executed; detach visible |
| `/api/dast/traffic/audit` (1200) | POST | B | Operator | Top-level list; nested dictionaries Any | Imported headers/bodies | Low S09 confirmed malformed nested input500 | Nested transaction model; bounds, safe errors | url integer/headers list422; no stack/secret echo |
| `/api/analysis/taint` (1224) | POST | B | Operator | Typed source_code/file_path; overall request1MiB | Submitted source/snippets | S01 renderer boundary; S07 event-loop CPU lead | Safe renderer; task executor/time budget; label heuristic | Hostile code inert in UI; no filesystem interpretation of label; size errors |
| `/api/apis/test` (1232) | POST | B | Operator + O | Exact origin; HTTP(S); no userinfo; DNS pin; TLS verify; bounded response | Operator headers/body, target response | No current unrestricted SSRF confirmed; S08 privacy | Maintain scope and no redirects; clear live-request warning | Unlisted403; private needs extra opt-in; redirect never followed |
| `/api/apis/fuzz` (1247) | POST | B | Operator | Typed transaction fields; audits supplied response, no live request | Captured response/headers | Medium P09: name/risk CLEAN overstates limited offline heuristic | Rename Analyze capture; report Not assessed not CLEAN | No request sent;403 does not prove BOLA; unknown semantics displayed |
| `/api/dast/fuzz` (1427) | POST | B | Operator + D | Serial/package; per-device concurrency and180s timeout; lists/path less strict | Runtime findings and device outputs | S03/P04; S07 secondary-action limits; path invariant gap | Reuse validated upload IDs; explicit actions; durable job+cancel+scope | Outside upload path rejected consistently; timeouts fail; cleanup |
| `/api/upload/apk` (1449) | POST | B | Operator | Filename/suffix, opaque UUID, exclusive write, ZIP bounds, disk count/quota | Uploaded source/secrets; host storage path | S07 aggregate spool/output risk; no current traversal confirmed | Reserved total quota; private storage; upload handle not path | Traversal,symlink,duplicate,bomb rejected; concurrent quota and cleanup |
| `/api/scans/run` (1565) | POST | B | Operator | Uploaded-root confinement; archive validation; output-root confinement; 2 active; bypass rejected | APK, analysis snippets, optional provider prompts | S02 privacy; S07 worker isolation; P08 recovery | Consent/effective config snapshot; sandbox worker and durable state | Missing400; scoped DAST only; restart stale jobs; cancel stops parser |

## Purpose and user-controlled parameter inventory
Exact annotations/defaults are in `evidence/routes.json`. Line numbers below are `mobileag/web/app.py`.

| Method / endpoint | Purpose | User-controlled parameters / model |
|---|---|---|
| WEBSOCKET `/ws/telemetry` | WebSocket endpoint for real-time agent execution stream and live telemetry. | None (WebSocket: token then text/ping) |
| GET `/` | Serve the single-page MobileAg Enterprise Dashboard. | None |
| GET `/api/status` | Return framework readiness, Neo4j connectivity, and configuration. | None |
| GET `/api/graph/status` | Check Neo4j graph database connectivity status. | None |
| GET `/api/scans` | List all available scans (past & current). | None |
| GET `/api/scans/{scan_id}` | Retrieve full scan details, attack surface graph, and findings. | scan_id: str |
| GET `/api/scans/{scan_id}/graph` | Retrieve graph topology, dynamically querying Neo4j if available, or falling back to embedded data. | scan_id: str |
| GET `/api/scans/{scan_id}/sarif` | Export scan findings in standard OASIS SARIF v2.1.0 format. | scan_id: str |
| GET `/api/scans/{scan_id}/apis` | Retrieve all discovered REST & GraphQL API endpoints for the specified scan. | scan_id: str |
| POST `/api/findings/{finding_id}/feedback` | Submit analyst triage verdict and update finding status in memory. | finding_id: str; FeedbackRequest: verdict, notes |
| POST `/api/copilot` | Analyze security findings and generate contextual explanations / remediation code. | CopilotRequest: prompt, scan_id |
| GET `/api/agents` | Return detailed status and metadata for all SAST analysis agents. | None |
| GET `/api/settings` | Return current dashboard configuration. | None |
| POST `/api/settings` | Update dashboard configuration in-memory. | entropy_threshold, enable_deep_taint, enable_reachability_filter, enable_consensus_voting, offline (only allowed keys) |
| GET `/api/dast/devices` | List connected Android devices, emulators, and verify root shell status. | None |
| POST `/api/dast/connect` | Connect to a local or remote emulator/device over TCP/IP. | DeviceConnectRequest: host_port |
| POST `/api/dast/root` | Restart adbd with root privileges on the selected device. | DeviceActionRequest: serial |
| POST `/api/dast/install` | Install an APK onto the target device with auto-granted runtime permissions. | InstallApkRequest: serial, apk_path, grant_permissions |
| POST `/api/dast/launch` | Launch an Android component or exported activity via am start. | LaunchActivityRequest: serial, component |
| POST `/api/dast/deeplink` | Dispatch a custom URI scheme or deep-link to the target device. | DispatchDeeplinkRequest: serial, uri |
| POST `/api/dast/execute_adb` | Execute an ADB shell command directly on the connected BYOD device. | ExecuteAdbRequest: serial, command |
| GET `/api/dast/logcat` | Dump recent logcat buffer and audit for CWE-532 leaks and fatal crashes. | serial: str; package_name: Optional[str]; lines: int |
| POST `/api/dast/logcat/clear` | Clear device logcat buffer. | DeviceActionRequest: serial |
| POST `/api/dast/screenshot` | Capture a live screenshot of the device screen. | DeviceActionRequest: serial |
| POST `/api/dast/storage` | Audit local sandbox storage (SharedPreferences, SQLite DBs, and cache) post-execution. | StorageAuditRequest: serial, package_name |
| POST `/api/dast/providers` | Audit exported Content Providers for unauthorized access and SQL syntax leakage. | ProviderAuditRequest: serial, package_name, authorities |
| POST `/api/dast/deeplinks` | Audit and fuzz deep links / custom schemes for OAuth theft, file access, and UXSS. | DeepLinkAuditRequest: serial, package_name, deep_links |
| POST `/api/dast/memory` | Audit volatile process RAM for cleartext passwords and lingering bearer tokens (CWE-316). | MemoryAuditRequest: serial, package_name |
| POST `/api/dast/crawl` | Autonomously navigate UI views with UIAutomator to expand dynamic coverage. | UICrawlRequest: serial, package_name, max_steps |
| POST `/api/dast/frida` | Generate or deploy dynamic Frida runtime scripts (SSL unpinning, crypto monitor, root bypass, unified). | FridaDeployRequest: serial, package_name, script_type |
| POST `/api/dast/traffic/audit` | Audit recorded HTTP transactions against OWASP API Security Top 10 rules. | TrafficAuditRequest: transactions |
| POST `/api/analysis/taint` | Find potential straight-line source-to-sink flows; results require manual validation. | TaintAnalyzeRequest: source_code, file_path |
| POST `/api/apis/test` | Replay a request only within the operator-configured scope. | ApiTestRequest: url, method, headers, body, timeout |
| POST `/api/apis/fuzz` | Run an autonomous OWASP API Security Top 10 (2023) audit on the given endpoint. | ApiFuzzRequest: url, method, headers, body, response_status, response_headers, response_body |
| POST `/api/dast/fuzz` | Trigger dynamic activity intent fuzzing and crash monitoring. | DastFuzzRequest: serial, package_name, apk_path, activities, deeplinks, authorities, targeted_extras, audit_storage, audit_memory, crawl_ui |
| POST `/api/upload/apk` | Store a validated application archive using an exclusive opaque identifier. | file: UploadFile |
| POST `/api/scans/run` | Trigger a new asynchronous security scan with live WebSocket telemetry. | RunScanRequest: apk_path, output_dir, auto_dast, auto_taint, bypass_root, bypass_ssl, serial |

## Framework-generated routes
FastAPI also registers GET/HEAD `/openapi.json`, `/docs`, `/docs/oauth2-redirect`, `/redoc`. They pass through the same bearer middleware, so the browser docs page cannot bootstrap API auth merely by opening a link. They are not unauthenticated schema exposure. Prefer documented authenticated API tooling, or disable docs for packaged release. Test401 anonymously and200 with bearer. These are framework routes, not target application endpoints.

## Boundary traces
- Upload name/bytes -> middleware/auth/body size -> suffix+archive checks -> UUID local file -> scan path confinement -> external parsers -> findings -> reports -> browser: output encoding must still be context-safe (S01).
- Source/capture JSON -> Pydantic outer model -> synchronous heuristic analysis -> response -> browser: nested `Any` breaks validation (S09); runtime authorization cannot be inferred from text.
- Finding ID/verdict -> token -> allowlisted verdict -> all in-memory scans -> success response: missing durable per-scan identity (S04).
- URL/headers/body -> token -> exact origin -> DNS check/pinned address -> TLS-verified no-redirect client -> bounded/redacted output. Keep these server controls even with a scope editor.
- Serial/package/action -> token -> serial allowlist/package syntax -> privileged ADB -> output. Syntax is not an intended-package policy; crawler must verify foreground each step (S03).
- Source secret candidate -> regex match -> **raw candidate prompt** -> configured router/provider -> later redacted finding. Redaction after the provider boundary is too late (S02).

No SQL/NoSQL injection, deserialization RCE, unrestricted SSRF or unauthenticated API authorization bypass was confirmed by this review. Graph Cypher values inspected are parameters. Trusted operator arbitrary ADB is a capability, not evidence of host command injection.
