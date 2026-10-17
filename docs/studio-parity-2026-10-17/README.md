# Studio workflow expansion — 2026-10-17

This supersedes the feature limitations in the initial Studio snapshot, not its historical test results. The core upload → review → approve → evidence flow remains simple; specialized workflows live under **Advanced tools**.

## Implemented coverage

The authenticated operation catalog derives forms from the registered API schema, rather than maintaining a separate incomplete endpoint list. It currently contains **93 operations: 89 enabled and 4 explicitly retired**. Selecting a form executes nothing. Each request requires a preview and separate approval; edits invalidate that approval. Server authorization, scope, session, evidence and resource checks still apply.

| Workflow | Browser access |
| --- | --- |
| Android/iOS offline static scan | Archive staging and approved assessment; scan details and recorded coverage |
| Guided assessment and automation | Create/list/inspect, plan/execute/status and evidence operations through reviewed forms |
| Device/API/traffic operations | Explicit scoped request forms; no automatic device or target selection |
| Taint | Source snippet, uploaded Java/Kotlin ZIP, and recorded APK analysis |
| Version diff | Stored scan comparison and isolated two-APK upload adapter |
| SARIF and MobSF import | Same CLI import engines; unverified candidate projection download, not silent database insertion |
| AAB inventory | Same bounded inventory engine, explicitly not code analysis |
| Reports | Existing SARIF and report routes; normalized JSON and Markdown downloads |
| Analyst decisions | Scan-scoped revision-aware feedback; optional structured evidence and existing proof gate |
| Source investigation | Artifact-bound file listing/read/search, graph topology and authenticated scan events |
| Configuration | Scope/settings edits and provider catalog; existing environment ceilings remain authoritative |
| Job management | Reviewed cancellation/retry and automation lifecycle routes |

### Intentional boundaries: not every CLI flag is exposed

- Browser scans remain offline. CLI cloud source review and online advisory lookup flags are not enabled by this work.
- Server lifecycle, bind host, bearer-token provisioning, provider secrets and environment ceilings remain terminal-managed.
- Uploaded files replace arbitrary host filesystem paths. Reports download rather than writing user-selected host paths.
- Retired generic finding feedback, log clearing, Frida injection and Frida preset generation stay disabled. Legacy full DAST is not revived.
- The existing scoped command endpoint remains subject to its server validation; this is not a new unrestricted shell gateway.

## Isolation and evidence

`mobileag/studio/routes.py` provides the catalog and bounded upload/report adapters. `jobs.py` reuses the existing bubblewrap namespace and systemd resource boundary for uploaded-source and APK-diff workers, with a single-job guard, timeout, disk limit, session checks, process-group termination and temporary-file cleanup. Missing isolation fails closed with 503: there is no unsandboxed fallback. Original uploads are not rewritten.

`worker.py` records input SHA-256, size, application/Python/parser versions, and extraction provenance for APK comparison. Source parsing is bounded to 1,000 Java/Kotlin files, 2 MiB per file and 32 MiB total. Outputs explicitly retain `runtime_status=not_tested` and `proof_status=not_proven`. Graph edges are inventory, not demonstrated reachability. Imported candidates and analyst decisions are not automatically exploit proof.

Tokens remain tab-memory-only. The event stream authenticates in its first frame rather than a query string. Request previews redact credential-like fields; those fields clear on execution. Results use text rendering, with only bounded PNG screenshots displayed inline. Source and graph labels do not become HTML.

## Final verification

- Latest complete suite: **1,385 tests passed** (`pytest -q -W ignore`, 58.67 seconds). Focused Studio tests: **30 passed**.
- **93 operation forms** rendered; no browser errors or external requests.
- **10 sampled accessibility views** passed axe-core WCAG A/AA checks, including 390 px and 320 px layouts.
- Installed-wheel smoke passed: API-only default, packaged UI assets, protected catalog and offline SARIF import.
- JavaScript syntax, Python compilation and `git diff --check` passed.
- Refreshed loopback server: `/ui` and `/ui/advanced.js` returned 200; unauthenticated catalog returned 401 and authenticated catalog returned 93 operations.

## Validation boundaries

See `validation/results.json` for the terminal browser result and `validation/provenance.json` for versions, source hashes and wheel hash. `operation-manifest.json` records the catalog reviewed by this revision.

- Browser checks instantiate every operation form without automatically sending mutation requests.
- Real local synthetic checks cover scope/settings saves, imports, AAB inventory, snippet taint, revision-aware triage, Markdown download, source reads/search, graph nodes/edges and authenticated telemetry.
- Out-of-scope device/API requests are rejected before execution. Guided assessment start, automation execution, scan start/cancel/retry requests are intercepted: these tests validate UI request construction, **not live execution**.
- Unit tests cover upload bounds, authentication, catalog coverage, temporary path handling, source traversal rejection, worker unavailability, busy rejection and session-revocation cleanup. A separate real, synthetic source-ZIP request completed through the namespace adapter (HTTP 200); see `validation/isolation-probe.json`. Its Java AST dependency was unavailable inside the isolated runtime, and coverage correctly reports lexical fallback. This is not AST validation or APK-wide coverage.
- No real device, Android OS build, APK assessment, cloud provider call or external API attack was performed. Successful production two-APK decompilation and every live assessment operation remain untested here.
- Accessibility checks are automated WCAG A/AA checks of sampled desktop/mobile views, not a complete manual accessibility certification. The added Logs & runtime view passed an axe-core check with no violations. Device logcat was intentionally not called in browser validation: the synthetic server has no approved device; the control stayed disabled. Scan-event WebSocket display and its no-device fail-closed state were browser-checked.

## Reproduce

```bash
python -m pytest -q
node --check mobileag/studio/assets/app.js
node --check mobileag/studio/assets/advanced.js
python tests/browser_studio.py --advanced --output /tmp/studio-validation \
  --axe /path/to/axe-core/axe.min.js
mobileag web --ui --host 127.0.0.1 --port 8081
```

Supply a privately configured `MOBILEAG_API_TOKEN`; connect at `http://127.0.0.1:8081/ui`. Without `--ui`, the default remains API-only. No credentials or real customer records are included in these artifacts.

## Logs and findings presentation

The **Logs & runtime** workspace groups live assessment events and exact-target logcat separately. Findings show per-severity candidate counts and expandable records with the recorded source, classification, trace, remediation and evidence fields. Device logcat requires the selected assessment package and a device explicitly present in persisted scope; loading the view only reads server scope, not the device. The action is disabled if the selected fields are missing. The existing backend checks session, exact device/package/action authorization, fetches target PIDs before collection, bounds output and redacts it. Results show attributed lines and log-derived diagnostic candidates; no evidence is cleared. Synthetic browser validation used an empty approved-device list, verified the action remained disabled and verified the scan-event UI. Real device logcat remains untested.

Finding details now also expose the full recorded analyzer candidate in a text-only expandable record, alongside source location, CWE, confidence, detection method, triage/evidence basis and remediation when recorded. These remain candidates unless independently validated. Djini's public material emphasizes severity/impact summaries, finding categories and expandable source-trace detail; MobileAg adopts those information-hierarchy ideas while preserving its own coverage/proof boundaries and visual design ([Djini SAST overview](https://djini.ai/free-ai-mobile-app-source-code-scanner/)).
