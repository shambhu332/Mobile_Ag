# Fix status — 2026-10-05

The adjacent REVIEW.md and reproduction JSON files are **pre-fix evidence**. Their scripts intentionally exercise the old defects and are not the current regression suite. Use `tests/test_security_regressions.py` for fixed behavior.

Checkpoint `779e3b9` contains the implementation, tests, original audit and pre-existing user changes. It was pushed to `shambhu332/Mobile_Ag/main`; GitHub visibility was then changed from PUBLIC to PRIVATE and verified through the authenticated GitHub CLI. Previously acquired copies or public forks are not retracted by this change.

The original local working tree was backed up before editing at `/tmp/mobileag-before-fixes-zrVgpNPY/source.tar`, with its existing patch alongside it. No original APKs, uploaded artifacts, credentials or databases were committed.

## Reported defects

| Original review item | Resolution | Regression coverage |
|---|---|---|
| 1 Upload traversal | Reject path-bearing names; exclusive UUID storage; archive/member/size checks; upload quota | Traversal, duplicate names, invalid archive, request-size tests |
| 2 Unauthenticated device APIs | Bearer authentication, Host/Origin validation, explicit device/connect scope; WebSocket authentication | Anonymous requests, foreign origins/hosts, device scope, WebSocket tests |
| 3 Server-side requests | Explicit exact-origin scope; DNS address validation and pinning; explicit private-target opt-in; verified TLS; no redirects; body/time limits | Scope rejection and controlled loopback positive/negative tests |
| 4 Offline flag | Scan setting disables provider initialization and OSV; offline secret candidates retained | Router, OSV, CLI and secret-scan tests |
| 5 Fabricated scans | Missing/invalid archives rejected; no implicit simulation; demo available only by explicit opt-in | Missing scan and failed-ingestion tests |
| 6 Raw previews shown as final | Previews separated from final findings; canonical final list, counts and persisted dashboard state | Final-only finding and restart-visible result tests |
| 7 Disconnected reports | Actual Markdown/JSON/SARIF generation, CLI format selection, IPA Markdown branch | Artifact existence and synthetic pipeline integration tests |
| 8 Wrong analysis roots | Separate Java/resource/smali paths and coverage counters | Resource routing and synthetic pipeline tests |
| 9 False Frida deployment | Native, serial-specific attachment; initialization acknowledgement; deterministic unload/detach; unavailable/error states | Mocked native acknowledgement/cleanup and unavailable-path tests |
| 10 Fabricated auth vulnerabilities | URL/admin/header checks no longer confirm bypass; automated results unverified | 403 response negative control |
| 11 Taint FP/FN | Sequential assignment/kill processing, inline source detection, method-boundary resets; explicitly heuristic | Inline, overwrite, method-isolation and pipeline fixtures |
| 12 Qdrant model crash | `cwe_id` mapping; current query_points adapter; explicit API-key support | Mocked Qdrant payload contract |
| 13 IPA executable mismatch | CFBundleExecutable lookup with containment checks; missing binary is an error | Differently named executable fixture |
| 14 Deep-link mismatch | Parser supplies canonical URI; worker uses exported activities and nonempty links | Parser contract fixture |
| 15 Boolean coercion | Strict boolean and bounded-confidence vote validation | String-false and invalid confidence negative controls |
| 16 Packaging/startup | Explicit package discovery, dependencies, templates and MASVS package data | Clean virtualenv installation, wheel build and installed-wheel startup smoke |

## Additional remediation

- Toasts use textContent; Markdown content is escaped before formatting; key metadata fields are HTML-escaped. Browser exploit validation was not performed.
- Supported runtime settings affect new scans. Unsupported provider/database UI settings are rejected/disabled rather than silently accepted.
- DAST, scan, upload, archive, WebSocket and proxy operations have bounds. APKTool/JADX have timeouts and process cleanup. Job persistence is local JSON, not a PostgreSQL workflow engine.
- iOS web uploads dispatch to the iOS analyzer instead of Android tooling.
- Credential findings redact sensitive excerpts before persistence/telemetry; original local decompilation artifacts still require appropriate storage protection. Redaction is not a guarantee that every possible secret format is recognized.
- Automated static/dynamic detectors emit UNVERIFIED candidates. Analyst confirmation requires evidence notes. Root/shell observations, symbol imports, LLM agreement and SQL errors do not independently prove ordinary-app exploitation.
- Database ports bind to loopback; compose requires configured Neo4j/Qdrant credentials. Deployment itself was not started.
- The ad-hoc proxy parser was replaced with bounded h11 request framing and scoped HTTP forwarding. Binary requests/responses and fragmented bodies have a regression test. Proxy authentication is required.
- Training export writes real newlines. Feedback no longer falsely claims vector-store synchronization.
- Developer tests no longer execute real ADB commands; old tests expecting fabricated success were updated to assert the corrected behavior.

## Deliberate capability boundaries

These are **not implemented features** and are no longer advertised as working:

1. Full control-flow/inter-procedural taint analysis. The detector remains a straight-line review heuristic, with possible false positives/negatives.
2. Persistent automatic root/SSL bypass orchestration. Automatic bypass flags are rejected; explicit Frida workbench validation detaches after acknowledgement and does not prove that every requested hook succeeded.
3. TLS interception by the built-in proxy. CONNECT returns 501; use a dedicated authorized capture tool for TLS inspection.
4. Main-pipeline historical vector learning. Coverage identifies it as not configured; UI feedback does not claim synchronization.
5. Multi-user RBAC. Authentication represents a trusted single operator, not tenant isolation or per-user roles. Do not deploy it as a shared public service.

## Validation and limitations

- Final full suite: **119 passed, 1 warning in 25.96s**, in a fresh Python 3.14 virtualenv containing the declared test/runtime dependencies. See `validation-summary.txt`.
- Python compilation, dashboard JavaScript syntax checking and `git diff --check` pass.
- Wheel builds successfully; installed-wheel smoke runs outside the checkout and checks dashboard 200, anonymous API 401, authenticated API 200, CLI entry point and packaged resources.
- Reproductions use synthetic APK/IPA/manifest/code fixtures, mocked ADB/Frida/providers/Qdrant, and a controlled loopback listener. No real-device instrumentation, current Android ordinary-app exploit, real cloud provider call, Neo4j/Qdrant deployment, or graphical browser interaction was validated.
- External decompilers are bounded and routed correctly by source review and mocks; their end-to-end output on a production APK was not verified here.
- Test success is not a guarantee that the entire codebase is defect-free. Remaining limitations are stated above rather than replaced with simulated results.
