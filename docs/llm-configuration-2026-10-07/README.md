# LLM provider controls in Configuration — 2026-10-07

MobileAg 0.1.0; baseline `3bdfd2764828c57799d8fbeaca636ba696ca62ce`. Validation is recorded before publication; Git history records the published revision. Earlier evidence, original artifacts and the user's private environment changes are preserved. `.env.example` contains a pre-existing user edit and is deliberately excluded from this commit; never publish API keys.

## User workflow

1. Open **Configuration → LLM provider configuration**. Choose the primary provider and optionally a distinct secondary. Exact server-configured models and per-provider setup instructions appear here. All ten adapters remain selectable for setup; unconfigured/unapproved selections cannot execute.
2. Use **Refresh providers** after updating the private server environment and restarting the server. Configuration is not a live connectivity/account entitlement check. Keys, model settings, allowed providers and local origin approvals remain server-controlled; no credential editor or cloud probe was introduced.
3. Use **Return to Start Assessment**. Its **Optional AI review** section shows the selected provider/model pair with a Configuration link and separate primary and secondary metadata-egress checkboxes. Review scope and approve execution there. Configuration alone never starts a scan or AI review.

Selections remain in memory while navigating this dashboard, reset on page reload, and are **not** persisted by the general Save Settings action. Changing primary clears both consents; changing secondary clears secondary consent. Choosing No AI removes the secondary and allows deterministic stages only. Both the assessment shortcut and the advanced static modal lead to Configuration, not to duplicate or disabled selectors.

The backend broker, server approval checks, aggregate-only payload, exact model configuration, scoped network transport, cancellation/revocation checks and bounded HTTP 429 fallback are unchanged. Secondary is attempted once only after actual primary HTTP 429; no fallback for authentication errors, timeouts or other failures. No raw APK/source/findings/URLs are sent and model output is never executed. See the [fallback report](../provider-fallback-2026-10-06/README.md).

## Review locations

- `mobileag/web/templates/index.html`: dedicated Configuration section, honest session-only text, advanced modal link.
- `mobileag/web/static/assessment.js`: single selector/model/setup group moved to Configuration, refresh/navigation wiring, assessment summary, preserved per-assessment consent and submit guards.
- `tests/test_interface_contracts.py`: shipped markup/consent-placement contract.
- `tests/browser_product_regression.py`: real loopback browser/router/storage; Configuration selection, navigation/summary, refresh and authorization negative controls, synthetic primary 429 to secondary 200. POST-specific mutation tracking distinguishes harmless list reads during navigation from assessment creation.

## Verified results

- **279 unit tests passed**, including the new Configuration placement contract. Deprecation/resource warnings remain (13,676).
- Real Chromium/loopback flow confirmed Configuration-only selectors, exact models/setup, summary/navigation links, retained selections across navigation/refresh, and explicit assessment-local consent. Unconfigured providers, forged unconsented submissions, duplicate pairs and catalog failures remained blocked. Synthetic Gemini 429 → Grok 200 recorded the actual secondary.
- All ten desktop and 320px mobile views had zero automated axe rule violations; no page errors or outside-loopback runtime requests. All mobile document widths were 320px.
- Shipped JavaScript syntax and local dashboard asset/module-order checks passed. Desktop Configuration screenshot was visually inspected. Packaging and live commercial model health were not re-tested for this UI-only move.

## Validation boundaries

See `validation/full-tests.txt`, `validation/browser/browser-results.json`, `validation/assets.txt`, and `validation/environment-source.json` for results and source/environment identity. `SHA256SUMS` identifies the evidence bundle. Browser screenshots include the Configuration provider panel on desktop and 320px mobile. The browser uses synthetic keys and mocked commercial transport/device operations, with actual loopback application routes/storage. No commercial model, real API key, APK target or device was contacted. Automated accessibility checks are not full accessibility certification; passing tests do not establish deployment readiness, provider health or ordinary-app exploitability. Python dependency deprecation/resource warnings remain.

Reproduce without real provider/device calls:

```bash
python -m pytest -q
python scripts/verify-dashboard-assets.py
node --check mobileag/web/static/assessment.js
python tests/browser_product_regression.py --server-python /usr/bin/python \
  --axe assets/node_modules/axe-core/axe.min.js \
  --output /tmp/mobileag-configuration-browser-check
```
