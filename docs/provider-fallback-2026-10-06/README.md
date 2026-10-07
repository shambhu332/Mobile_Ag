# Explicit primary/secondary AI review — 2026-10-06

MobileAg 0.1.0; baseline `3921bbe49d303f882e4bb61b156fa8b5e77f54bb`. Validation was recorded before commit/push; publication status is tracked by Git history. Earlier artifacts and original `dist/` are preserved. A pre-existing user edit to `.env.example` was left untouched and is not included in this implementation; keep real keys only in the ignored private `.env`/server environment, never in the tracked example or evidence.

## Behavior and boundaries

Start Assessment → Optional AI review now offers **Primary AI provider** and **Secondary AI provider (HTTP 429 fallback only)**. Both configured models are visible. Primary egress consent and separate secondary-on-rate-limit consent are required before starting a pair. Choose Gemini → Grok or the reverse; no order is silently selected.

- One primary request. Only an actual HTTP 429 response permits **one** request to the selected approved secondary. No retries to the throttled provider, quota-key rotation, provider loops or tertiary provider. Each new assessment begins with its selected primary; there is no permanent provider switch/cooldown scheduler.
- No fallback for 400/401/402/403, other HTTP errors, timeout/network failure, blocked content or malformed/empty text. A body merely mentioning 429 is not a rate-limit response. If secondary also fails or rate-limits, the AI stage records an error rather than fabricated advice.
- Both destinations need existing server approval, exact model/key/local-origin configuration. Same-provider pairs, secondary without primary and missing fallback consent are rejected before static/policy mutation or provider traffic. The UI guards are repeated by the backend; they are not authorization.
- Current provider approval/configuration and session/scope/cancellation guards are checked before each attempt and after transport. Revocation stops continuation. The broker busy latch covers the entire pair and resets on cancellation/error.
- Identical allowlisted aggregate metadata goes to either provider: no APK/source/raw findings/target URLs/credentials. Provider errors/bodies/headers are not stored. Keys remain server-side; AI advice is untrusted, never executed and redacted.
- Evidence records selected IDs and consent, actual provider/model used, whether fallback occurred, and bounded attempts with outcomes/HTTP statuses. The UI explains the transition without requiring raw JSON inspection. Either approved cloud provider may charge fees.
- This changes the guided-assessment broker only, not the legacy CLI router, offline parser, target replay authorization or root/TLS capabilities.

Review locations: `mobileag/llm/broker.py` (`validate_review_selection`, `review`, `_review_once`, sanitized exceptions), `mobileag/assessments/models.py`, `service.py` (preflight/selection evidence/broker call/error evidence), `mobileag/web/static/assessment.js` (selection/configuration/consent/submit/results), `mobileag/web/templates/index.html` (Settings description).

HTTP 429 is the documented rate-limit response for [Gemini](https://ai.google.dev/gemini-api/docs/rate-limits) and [xAI](https://docs.x.ai/developers/rate-limits). This product uses a bounded, separately consented second destination rather than retrying the throttled provider; it does not increase either provider's account quota or establish model entitlement.

## Private server setup

Merge these non-secret approvals/model settings into your private environment:

```dotenv
MOBILEAG_LLM_ALLOWED_PROVIDERS=gemini,grok
MOBILEAG_LLM_GEMINI_MODEL=<YOUR_EXACT_GENERATECONTENT_MODEL_ID>
MOBILEAG_LLM_GROK_MODEL=<YOUR_EXACT_CHAT_COMPLETIONS_MODEL_ID>
OFFLINE=true
APPROVED_LLM_PROVIDERS=[]
```

Replace placeholders and set `GEMINI_API_KEY` and `XAI_API_KEY` privately. Model IDs are account-specific; configuration is not a health check. Do not paste keys into chat, UI, tracked files or screenshots. Replace the earlier exposed Gemini key rather than reusing it. Leave `.env.example` secret fields blank.

Restart the loopback dashboard from the updated checkout, reload, Refresh providers, select primary/secondary and explicitly approve both egress checkboxes. Installed copies need a newly built/reinstalled package first. No existing service was restarted, private keys moved, `.env` edited, account/model probed or deployment changed by this implementation.

## Verification

- **278 unit tests passed**, including 32 new fallback tests: both Gemini/Grok orders, primary success, restarting each review with primary, no fallback on non-429/error/text cases, terminal secondary 429, consent/configuration/mutation controls, revocation/cancellation/busy-latch cleanup and actual persisted assessment evidence. Python/pytest deprecation/resource warnings remain (`validation/full-tests.txt`).
- Controlled real HTTP transport test uses two researcher-owned temporary loopback servers: primary `/api/chat` returns 429, secondary `/v1/chat/completions` returns 200. Exact independently approved origins are enforced. Servers/threads cleaned up; no vendor/model/device contacted.
- Actual Chromium/browser + real loopback web router/storage: unconsented forged submit blocked, duplicate pair blocked, changing secondary resets its consent, refresh retains a valid pair/consent, synthetic Gemini 429 → Grok 200 reaches the broker and displays actual fallback evidence without credentials. Existing authentication, scope, negative controls and navigation tests retained.
- All ten desktop and 320px mobile view states: zero automated axe rule violations, no page errors, no outside-loopback runtime requests, no page-level horizontal overflow. Not full accessibility/production certification.
- Temporary wheel built without dependency downloads, installed/imported outside checkout, served 18 local scripts and denied protected unauthenticated APIs. Temporary build/install removed; original `dist/` preserved (`validation/wheel-smoke.txt`).
- Local asset verification and JS syntax passed. Source/environment hashes and evidence checksums identify this working tree. No live API key health, commercial inference, remote CI, current-device exploit or bounty finding is claimed.

Reproduce:

```bash
python -m pytest -q
python scripts/verify-dashboard-assets.py
node --check mobileag/web/static/assessment.js
python tests/browser_product_regression.py --server-python /usr/bin/python \
  --axe assets/node_modules/axe-core/axe.min.js \
  --output /tmp/mobileag-fallback-browser-check
```
