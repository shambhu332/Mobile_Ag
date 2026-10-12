# Dashboard self-connection, navigation and curl

This feature operates the **MobileAg dashboard**, not an Android application's
login. It does not obtain credentials, bypass token authentication, or start
scans/device/API target tests. Existing explicit assessment approvals remain.

## Use

Start the dashboard normally:

```bash
python -m mobileag.cli web --host 127.0.0.1 --port 8080
```

In another terminal, securely supply the same server session token. The client
prompts privately if `MOBILEAG_API_TOKEN` is not set. Never put a real token into
a command argument, URL, committed file, screenshot, shared log or shell history.

```bash
# Each command privately prompts unless MOBILEAG_API_TOKEN is already configured.
python -m mobileag.cli dashboard api
python -m mobileag.cli dashboard api --path /api/scope --transport curl
python -m mobileag.cli dashboard api --path '/api/scans?limit=10&summaries=true'
```

For automatic browser session connection and section navigation, install the
optional browser dependency and Chromium in your local environment:

```bash
python -m pip install '.[dashboard]'
python -m playwright install chromium
python -m mobileag.cli dashboard navigate --view overview --view findings --view settings
# Omit --view to visit all 11 sections; --headed shows the temporary browser.
# --chromium /path/to/chrome uses an explicitly installed executable.
```

Use `--url http://127.0.0.1:PORT` for the actual printed server port. `localhost`
is pinned to numeric IPv4 loopback; IPv6 requires an explicit `[::1]` origin.
Remote dashboard origins are deliberately unsupported by this client.

To avoid retyping the token for each client command in a Bash session, read it
privately once (do not use a literal token in `export`):

```bash
read -r -s -p 'Dashboard session token: ' MOBILEAG_API_TOKEN; printf '\n'
export MOBILEAG_API_TOKEN
# Run the dashboard commands, then remove the token from this shell when done.
unset MOBILEAG_API_TOKEN
```

## Behavior and boundaries

- Automatic login uses the **real token form**, with a provided current session
  token. Invalid/expired tokens fail; there is no anonymous-login shortcut.
- Browser navigation clicks exact known section controls, not guessed buttons or
  model-generated executable actions. This is deterministic navigation, not an
  unrestricted AI UX agent or a full accessibility certification.
- Only allowlisted local dashboard GET endpoints are accessible. Device shell,
  logcat, Frida, target replay, uploads, scans, settings changes and other writes
  are blocked. Local readiness/device inventory may perform harmless host checks;
  no device is selected or connected.
- Browser redirects are blocked before following them; off-origin requests and
  writes are blocked before transmission. Telemetry WebSockets are disabled in
  navigation mode. The client ignores proxies, redirects and curl configuration
  files. HTTPS certificate checks remain enabled.
- Curl receives Authorization via stdin, not argv or a temporary configuration
  file. It is executed directly, never through a shell. Responses are bounded and
  sensitive fields/reflected tokens are redacted before printing.
- Browser contexts close at completion. Tokens stay ephemeral; no profile,
  cookies, storage-state files, screenshots, traces or raw DOM reports are saved.
  Re-run with a fresh token after server restart, rotation or session expiry.
- Navigation reports show visited sections and bounded errors, not a security
  verdict. They do not assert target login, workflow correctness or bug proof.

## Validation

Synthetic loopback server, researcher-controlled fixture state, mocked unit
transports, and cached Chromium only. No real device, mobile account, live target,
or commercial model is involved.

- Full suite: **622 tests passed** (29,554 warnings remain).
- Real-form browser connection: passed; all **11 sections** visible, no blocked
  HTTP requests or page errors. No additional assessment/navigation jobs started
  and no real telemetry subscriber was created.
- Real curl and HTTP client GETs against the synthetic server: passed; wrong
  token rejected. Unit controls cover off-origin paths, device endpoints, writes,
  redirects, oversized responses, subprocess errors and token reflection.
- Python 3.14.7, Playwright 1.63.0, cached Chromium, curl 8.22.0 on this host.
- Python compilation, dashboard asset verification and whitespace checks passed.
- Wheel build, installed-wheel smoke outside the checkout, and packaged
  `dashboard --help` passed (MobileAg 0.1.0).

The browser regression is `tests/browser_dashboard_navigation.py` and is included
in CI. A sync WebSocket close callback hung on the local Python 3.14 browser
stack during development; navigation now intercepts sockets without connecting
them to a server rather than calling close from that callback. The real-form
login check does not weaken the application's CSP or token validation.

## Dashboard UI

Use the global **Dashboard tools** button for session controls, section navigation
and explicit HTTP/curl reads. [UI details and validation](../dashboard-ui-2026-10-11/README.md).
