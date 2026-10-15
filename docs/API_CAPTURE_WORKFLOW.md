# Scoped API discovery workflow

MobileAg performs static API route inventory during APK assessment. It also
supports a separate, operator-driven HTTP capture path; capture does not launch
an APK or send requests by itself.

1. Add exact backend origins and permitted methods to the operator scope and
   enable the `api_capture` action. The origins must also be in
   `MOBILEAG_ALLOWED_ORIGINS`; private targets require the existing explicit
   private-target opt-in. Never add a target without authorization.
2. Configure a researcher-controlled client/device to use `127.0.0.1:8082`
   as its HTTP proxy and send `Proxy-Authorization: Bearer <MOBILEAG_PROXY_TOKEN>`.
   Start/stop and inspect it through the authenticated
   `/api/dast/api-capture/{start,stop,transactions,audit}` endpoints.
3. Exercise only approved test flows with synthetic accounts/data, then analyze
   the redacted captures. Inspect `/api/dast/api-capture/transactions`, review
   `/api/dast/api-capture/openapi` (an inventory based on observations, with
   bounded JSON shape inference that excludes example values; it is not a
   normative schema/complete API model), optionally export the redacted
   `/api/dast/api-capture/har`, then use `/api/dast/api-capture/audit`. The proxy
   enforces both the persisted origin/method scope and the server environment
   origin ceiling.

This proxy does **not** intercept HTTPS CONNECT/TLS, configure a device, bypass
certificate pinning, or automatically fuzz/replay captured routes. Use an
authorized TLS interception workflow to import captures, or the separately
scoped API replay feature for explicit requests. Route strings and captured
requests are inventory/evidence, not proof of backend authorization behavior.
