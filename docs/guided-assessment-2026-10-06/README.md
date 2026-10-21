# Guided APK + API assessment and model-provider integration

Implemented 2026-10-06. Extends the previously validated scoped automation; does not claim to complete every possible mobile/API penetration test.

## Primary UX

**Start Assessment → upload owned APK → approve APK/API/device scope and stages → Start scoped assessment → review stage evidence.**

- Start Assessment is the primary sidebar/new-target entry. Empty workspaces open it after authentication. Upload/drop alone never starts any scan.
- Device, navigation, taint, API and analyzer workbenches are now optional **Advanced tools**, not a confusing collection of independent “live/full-spectrum” starts. The former BYOD header is moved into advanced device tools; no implicit device selection.
- Show API fields only when API is selected, device fields only when DAST is selected, and model-egress consent only when a provider is selected. Native labels, confirmation/recovery, keyboard-scrollable evidence and a distinct primary CTA are retained.
- Original advanced static APK/IPA scanning remains accessible. Guided live orchestration currently supports Android APKs only.
- The run records static hash, exact package, global scope approval, per-stage status, actual receipts, untested cases and links to SAST/navigation findings. Export includes latest redacted navigation evidence, not fabricated “all tests passed”.

## What Start actually does

1. Validate the uploaded archive, exact package/component, server ceilings, read-only request metadata, stage/impact confirmations and provider settings. Explicitly replace the saved operator scope; this can stop other active jobs. One guided assessment at a time; reservation is rechecked after awaited validation.
2. Execute **SAST** through the existing real offline bubblewrap/systemd worker. No model key, home, dashboard database, network or ADB is exposed to the parser. Hash rechecked before/after static work.
3. Stop live phases if static analysis is incomplete, the package differs from the approved ID, the upload changed, session/scope is revoked or cancellation was requested. A static candidate is not a confirmed vulnerability.
4. If selected, run **API tests** against operator-imported exact scoped GET/HEAD URLs. This phase requires no device. Baseline, protected anonymous, and bounded query variants use the existing pinned TLS/no-redirect transport and per-run budget (0–10 requests, one-second interval). Fresh dedicated Authorization is memory-only. Values/headers/raw bodies/URL paths are not persisted; response shape is capped at 8 KiB/receipt. Preserve partial receipts on failure. “Observed” is not “passed” without an oracle, and anonymous 2xx is only a lead until protected-data impact is established.
5. After a completed API stage, the authenticated `POST /api/assessments/{id}/authorization-probe` can run one explicit **read-only two-account comparison**: owner baseline, other-account baseline, then the other account against the owner's exact resource URL. The two URLs must match protected GET captures from that assessment and stay on its exact currently allowed origin. It sends exactly three GETs with fresh, distinct test Authorization values; requires operator confirmation of synthetic data, distinct controlled accounts, account identities, and same-owner resource semantics. Only status/equality evidence is persisted; secrets, URLs, markers and bodies are not. A match is an unverified disclosure candidate, not independent proof.
6. If selected, **DAST** preflights the exact dedicated device. Separately approved install-if-absent refuses an existing package and uses neither `-r` nor `-g`; normal Android install-time permission behavior still applies. Before live mapping, it compares the installed APK SHA-256 with the analyzed upload using ordinary ADB shell access. Mismatches, unreadable identity, and split installs pause DAST and record why; package/version labels alone are not build identity. Optional launch is explicit. Then map the approved live app through Android/UIAutomator and create the navigation review run. New/ambiguous controls, consent/destructive actions, roots, hooks and TLS bypass are not clicked/executed. **Taps still require exact action review and run-ID approval**; DAST mapping is not a full unattended exploit suite. Scope grants navigation capability, not automatic action approval.
7. If selected and server-approved, a separate **AI broker** receives only freshly constructed aggregate counts/status/coverage. It never receives the APK, source, finding descriptions, app/user IDs, URLs, tokens, API bodies or screen text; its text is untrusted advice, never a finding or executable tool instruction. No implicit provider fallback or multi-provider billing.
8. Persist outcomes; queued phases after failure are explicitly not executed. Restart interrupts without resuming live operations. Stop propagates to the associated static job and future stages; issued device/network actions cannot be undone. The 480-second overall budget does not turn failures into clean results.

ADB privileges/input are device-wide; package foreground checks are non-atomic guardrails, not ordinary-app isolation. Use researcher-controlled dedicated devices/accounts and synthetic/staging data. No actual owned-production/staging target was supplied for this change.

## Provider catalog (ten adapters)

No default/latest model is hardcoded in the broker. Choose an exact model available to your account/local server. Configuration is not network health, account entitlement or model availability.

| Provider ID | API protocol | Server credential | Exact model variable |
|---|---|---|---|
| `openai` (GPT) | OpenAI Chat Completions | `OPENAI_API_KEY` | `MOBILEAG_LLM_OPENAI_MODEL` |
| `gemini` | Gemini generateContent | `GEMINI_API_KEY` | `MOBILEAG_LLM_GEMINI_MODEL` |
| `grok` | xAI OpenAI-compatible chat | `XAI_API_KEY` | `MOBILEAG_LLM_GROK_MODEL` |
| `claude` | Anthropic Messages | `ANTHROPIC_API_KEY` | `MOBILEAG_LLM_CLAUDE_MODEL` |
| `deepseek` | OpenAI-compatible chat | `DEEPSEEK_API_KEY` | `MOBILEAG_LLM_DEEPSEEK_MODEL` |
| `groq` | OpenAI-compatible chat | `GROQ_API_KEY` | `MOBILEAG_LLM_GROQ_MODEL` |
| `mistral` | OpenAI-compatible chat | `MISTRAL_API_KEY` | `MOBILEAG_LLM_MISTRAL_MODEL` |
| `openrouter` | OpenAI-compatible chat; may use additional processors | `OPENROUTER_API_KEY` | `MOBILEAG_LLM_OPENROUTER_MODEL` |
| `ollama` | Local `/api/chat`, no streaming | No key required | `MOBILEAG_LLM_OLLAMA_MODEL` |
| `local_openai` (LM Studio/vLLM/compatible server) | Local OpenAI-compatible chat | Optional `MOBILEAG_LOCAL_LLM_KEY` | `MOBILEAG_LLM_LOCAL_OPENAI_MODEL` |

Set `MOBILEAG_LLM_ALLOWED_PROVIDERS` to comma-separated exact IDs. Local models additionally need `MOBILEAG_LLM_LOCAL_ORIGINS` and the exact `MOBILEAG_LLM_OLLAMA_ORIGIN` / `MOBILEAG_LLM_LOCAL_OPENAI_ORIGIN`; only literal loopback/localhost endpoints are accepted and **all resolved addresses must be loopback**. Cloud adapters use fixed HTTPS origins and verified pinned TLS; keys cannot be redirected to an arbitrary gateway. Target API origin scope does not authorize model egress or vice versa.

Keys stay in the server environment/private `.env`, never dashboard storage/APKs/reports. Update only your private configuration using `.env.example`, restart your server and Refresh providers. Do not paste credentials into chat or commits. `OFFLINE` still governs the isolated worker/legacy CLI router; the separate broker needs its own server approval **and** per-assessment aggregate-egress consent. This is explicitly optional—not a hidden reversal of offline parser isolation.

Official protocol references checked during implementation: [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create), [Gemini](https://ai.google.dev/api/generate-content), [xAI text/compatibility](https://docs.x.ai/developers/model-capabilities/text/generate-text), [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create), [DeepSeek](https://api-docs.deepseek.com/), [Groq compatibility](https://console.groq.com/docs/openai), [Mistral](https://docs.mistral.ai/api), [OpenRouter](https://openrouter.ai/docs/api_reference/overview), [Ollama chat](https://docs.ollama.com/api/chat). Provider/account-specific unsupported models/parameters return error, never a fake success. Commercial adapters were protocol-tested with mocks, **not live commercial credentials**.

## Review locations / API inventory

- `mobileag/assessments/{models,store,service,routes}.py`: strict contracts, bounded private SQLite state, stage orchestration, package/hash/session/scope gates, restart/cancel.
- `mobileag/llm/broker.py`: server provider catalog, metadata allowlist, cost/concurrency/timeout limits, normalized safe text and no tools/fallback.
- `mobileag/security/network.py`: separate trusted origin policy for broker; pinned DNS/TLS, no proxies/redirects and loopback-only local resolution. Existing target API defaults unchanged; request bodies cannot supply broker scope.
- `mobileag/automation/engine.py`: API receipt shape cap and explicit server-supplied API guard for device-independent orchestration. No authorization hook or test mode in deployed routes.
- `mobileag/dast/adb_manager.py`: additive non-replacing installation option; existing advanced behavior preserved.
- `mobileag/web/static/assessment.js` + templates/styles/upload/workspace scripts: primary workflow, no auto-scan on upload, conditional fields, safe text rendering and optional advanced tools.

| Endpoint | Method | Auth / authorization | Inputs / sensitive data | Validation |
|---|---|---|---|---|
| `/api/assessments/providers` | GET | Current local bearer/Host/Origin | Configuration-only public provider/model names; never keys, no provider contact | Auth negative/catalog tests |
| `/api/assessments` | GET | Current local operator | Up to 100 historical summaries/hashes | Private store, no target operations |
| `/api/assessments` | POST | Current bearer plus explicit APK/API/device/provider approval narrowed by server environment | Strict plan, upload path, exact IDs/scope, optional ephemeral test header | Confirmation, budgets, package/host/device ceilings, privacy-safe 422; no raw input echo |
| `/api/assessments/{id}` | GET | Current local operator | Historical stage receipts + latest redacted navigation report | Opaque ID; missing 404; no live operation |
| `/api/assessments/{id}/cancel` | POST | Current local operator | Active ID; mark stop and associated static cancellation | Inactive 409; cannot undo issued operations |

Like the rest of this workbench, deployment is one local operator/one worker, not multitenant authorization. Private evidence storage/retention caps do not constitute anonymization. Backend authorization, TLS, provider-credential isolation and operation consent **cannot be securely fixed through UI/UX alone**; these are server-enforced controls, not hidden buttons.

## Validation and remaining limitations

See `validation/` for unit, browser, installed-wheel and real local integration evidence. The browser tests exercise the real auth/router/policy/store/stage UI, with synthetic static/device adapters. A separate controlled run uses the **real isolated SAST worker** and real loopback API/model HTTP transports on our previously compiled permission-free fixture. No commercial provider calls or device commands in that run. Earlier real Genymotion integration remains separately recorded on Android9/root shell, not a current ordinary-app exploit result.

```bash
python -m pytest -q
python scripts/verify-dashboard-assets.py
python -m build --wheel
python tests/browser_product_regression.py --server-python /path/to/venv/bin/python \
  --chromium /path/to/chromium --axe assets/node_modules/axe-core/axe.min.js --output /private/evidence
# Only our synthetic navigation fixture; no target/device/commercial provider:
PYTHONPATH="$PWD" python tests/guided_local_regression.py \
  --apk docs/automation-2026-10-05/validation/navigation-synthetic.apk --output /private/fixture-evidence
```

Still not implemented/proven: native iOS live automation, credential/form filling, transparent TLS capture, a general authorization/ownership test matrix beyond the bounded exact-marker two-account probe, write/payment/business transactions, full screen-reader/contrast/native performance testing, every platform DAST check, representative corpus/load acceptance or numerical production certification. LLM integration does not turn those gaps into coverage. Owned APK/package, exact staging origins, dedicated account identifiers and current unrooted devices remain necessary for real-app acceptance; never use discovered credentials or test unrelated targets.

## Security continuation

[Request/session boundary follow-up](../continuation-2026-10-06/README.md) records reproduced rotation/expiry/hash-cancellation races and their fixes, 14 new boundary tests, the current 226-test suite, and a fresh synthetic browser regression. Earlier evidence above remains preserved and is not rewritten as evidence for this changed source tree.

## Selecting an AI provider

The [provider selector follow-up](../provider-selector-2026-10-06/README.md) makes all ten integrations selectable to inspect setup requirements, while keeping AI execution blocked until server configuration and explicit metadata-egress consent are present. Refresh preserves selection; Settings links to the real per-assessment selector rather than a disabled legacy picker. This is not automatic provider activation or a live connectivity check.

### Workspace interface refresh

The current ten-view interface refresh, grouped assessment workflow, collapsible mobile navigation, cancel-safe triage, captured-response guardrails and final validation are recorded in [the interface refresh report](../interface-refresh-2026-10-06/README.md). Historical evidence in this directory remains tied to its original source boundary.

### Opt-in rate-limit fallback

The primary/secondary broker now supports one separately approved secondary attempt after primary HTTP 429 only. Both destinations require server configuration and explicit consent; no loops or auth/timeout/content-error fallback. See [current fallback setup and validation](../provider-fallback-2026-10-06/README.md). Earlier evidence remains tied to its original source boundary.
