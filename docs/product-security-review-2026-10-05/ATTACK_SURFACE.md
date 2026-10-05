# Current system / attack-surface map
Baseline: `56d2febcb204e2a156d61677eac6197ea2543bd0`. Read this before findings.

```text
Untrusted APK/IPA / source / captured HTTP / operator-supplied URLs
  -> bearer-authenticated FastAPI HTTP or local CLI
  -> bounded archive validation -> local JADX/APKTool/extraction
  -> manifest, Java/Kotlin, smali, native, dependency, taint and heuristic analyzers
  -> optional cloud LLMs / public OSV lookup (offline mode suppresses these)
  -> filtering -> candidate Finding -> generator -> JSON/Markdown/SARIF
  -> local output/dashboard.json -> authenticated API -> HTML/JS dashboard
  -> bearer-in-first-message WebSocket -> global telemetry subscribers

Trusted operator dashboard
  -> scoped HTTP replay/fuzz -> exact allowed origin, DNS/IP checks, no redirects
  -> explicitly allowed ADB serial -> shell/install/root/logcat/storage/IPC/crawl
  -> optional Frida attach (initialization then detach; not persistent proof)
  -> optional Neo4j graph; Qdrant/historical helpers not full deployed workflow

Outside trust boundary: sample author, browser DOM input, LLM output, target HTTP
responses, device outputs, third-party CDN scripts and external parsing tools.
Within intended trust: one local operator; token authorizes all operator functions.
```

## Code and ownership boundaries
- `mobileag/cli.py`: scan, iOS, DAST, diff, taint, web entrypoints.
- `web/app.py`, `web/security.py`: API, shared operator authorization, host/origin validation, jobs/uploads, global state.
- `web/templates/index.html`: eight primary views, drawers/modals and all client state; no separate mobile app.
- `ingestion/*`, `analysis/*`: hostile-file parsing, static heuristics. Decompilation is not original source and findings need validation.
- `core/orchestrator.py`: sequential orchestration with concurrent analysis tasks; not a deployed persistent LangGraph job service.
- `filters/*`, `llm/*`, `generators/*`: confidence decisions and optional remote processing; confidence is not exploit proof.
- `dast/*`: high-privilege operator tools. ADB/root/Frida results do not establish ordinary-app exploitation.
- `security/*`: archive bounds, exact-origin replay and credential-pattern redaction.
- `reporting/*`, `knowledge/*`: evidence outputs and optional graph/vector helpers.
- `config/*`, `.env.example`, Docker/packaging: runtime secrets, scope, dependencies and deployment.

## Implemented product flows
Token prompt -> dashboard -> upload -> static scan -> findings -> analyst triage/export;
optional explicitly scoped device validation or endpoint replay. Settings change new-run
analysis flags, not persistent application identity/authorization. API models/routes are
recorded verbatim from AST in `evidence/routes.json`; the API matrix covers each.

## Not implemented / not applicable
No shipped Android/iOS app, native app UI, user registration, password reset, OTP/MFA,
refresh tokens, account balances, subscriptions, payment/webhook/referral workflows,
push messaging or GraphQL server. The API mapper discovers target routes; discovery
does not authorize testing those services. Multi-tenant ownership/RBAC is absent by
design: do not publish this as a tenant-isolated SaaS without redesign.

## Data destinations and trust
Uploaded binaries/extracted sources -> local uploads/output (potential target secrets/PII).
Finding snippets -> local reports/browser and, when enabled, cloud LLM prompts.
Candidate secret verification -> raw candidate to configured provider (see findings).
API replay -> explicitly allowlisted remote service (operator headers/body can be secrets).
Device output -> browser/runtime memory; selected findings -> local evidence.
Session bearer -> process and browser memory, full trusted-operator authority.
No real credentials or target-device data were used for this review.
