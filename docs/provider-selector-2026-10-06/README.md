# Provider selector usability fix

Baseline: `ef1a154b7ce56e3cec0ebb33d67efffed735c7dd`, MobileAg 0.1.0. The user identified **Start Assessment → Optional AI review** as the blocked control. Original working tree was clean. This report records validation before commit/push; publication status is tracked by Git history. Earlier reports/artifacts remain preserved.

## Cause and changes

- The old selector disabled each option when the authenticated server catalog returned `enabled=false`. That is expected execution policy for missing approval/model/key/origin, but it also prevented selecting a provider to learn how to configure it. The checked shell has **0/10 configured adapters**, not a proof of the configuration of a separately running server.
- All ten existing adapters are now selectable for **setup inspection**. Unconfigured choices show precise missing-variable instructions and a separate read-only configured-model field. Variable names/examples are public configuration metadata, never credential values. No new adapter/Qwen-specific integration or live model health check was added.
- AI start remains disabled unless the latest catalog marks the selection configured and the operator explicitly consents to metadata egress. Programmatic submit also checks these gates; server authorization remains authoritative. Choosing an unconfigured adapter never silently downgrades the assessment to No AI.
- Refresh preserves provider selection, resets consent when the selected model changes or becomes unconfigured, and blocks selected AI after catalog loading/failure. No AI still allows deterministic testing.
- Settings and the advanced static modal no longer show misleading disabled primary/fallback provider pickers or stale model names. Both link to the real guided-assessment selector. Advanced static analysis remains offline, with no automatic fallback/multi-provider billing.

Review locations: `mobileag/llm/broker.py` (`setup_fields`, `configured`, `catalog`), `mobileag/web/static/assessment.js` (`updateProvider`, `loadProviders`, submit guard), `mobileag/web/templates/index.html`, `mobileag/web/static/history-settings.js`.

## Using it

1. Open **Start Assessment → Optional AI review**. Select GPT/OpenAI, Grok, Gemini or another listed adapter. Unconfigured entries say **Setup required** rather than being impossible to select.
2. Read the visible missing settings and expand **Server setup for …**. Set the named variables in your private server environment or `.env`, never in chat, browser storage or reports. Merge the provider into any existing approved-provider list; don't accidentally replace other approvals.
3. Set an actual exact model available to your account/local server and its private key where required. Local adapters additionally require their loopback origin approval. This UI does not write keys or authorize server egress for you.
4. Restart the server, refresh the page, then **Refresh providers**. Confirm the model shown and explicitly approve aggregate-metadata egress before starting.

For Grok, the relevant names are `MOBILEAG_LLM_ALLOWED_PROVIDERS` (include `grok`), `MOBILEAG_LLM_GROK_MODEL` and `XAI_API_KEY`. For GPT/OpenAI use `openai`, `MOBILEAG_LLM_OPENAI_MODEL` and `OPENAI_API_KEY`; for Gemini use `gemini`, `MOBILEAG_LLM_GEMINI_MODEL` and `GEMINI_API_KEY`. These are local configuration contracts, not claims of current vendor model entitlement/availability. Keep `OFFLINE=true`: the isolated parser remains offline and optional broker consent is separate.

If running from this checkout, restart `python -m mobileag.cli web --host 127.0.0.1 --port 8080`. If running an installed wheel, rebuild/reinstall the changed package first; the existing `dist/` artifact was deliberately not overwritten or revalidated here. No unrelated existing service was restarted.

## Validation

- **237 unit tests passed** after final edits; 11 added catalog/setup/privacy/approval tests. Deprecation warnings remain (`validation/full-tests.txt`).
- Actual local Chromium browser regression: all ten adapters selectable for setup; unconfigured choice blocked; forged submit blocked; configured exact model shown; explicit consent required; refresh preserved choice; a synthetic catalog 503 blocked selected AI without dropping it; Settings linked to the actual selector. A second approved assessment reached the real broker via a **synthetic protocol callback**, not a commercial account/model/network call.
- Ten tested views had zero automated axe violations; no page errors or outside-loopback runtime requests. Expected wrong-token 401, simulated catalog 503 and blocked-inline-handler CSP console diagnostics are preserved. These checks are not full accessibility or production certification.
- Pre-fix browser check against a temporary archive of baseline `ef1a154` failed at the disabled-option assertion (`validation/pre-fix-browser.txt`). The synthetic fixture deliberately configured one adapter and left nine unconfigured to test both ready/setup states. Temporary source/server/data were cleaned up.
- JS syntax, local asset checks and `git diff --check` passed. Current source/environment hashes and evidence checksums accompany this report.

No real device/decompiler/target API/provider inference, account entitlement validation, wheel rebuild, deployment update, push or remote CI execution is claimed for this follow-up. Server-side aggregate-only privacy, private credentials, exact approvals and offline worker isolation are unchanged.
