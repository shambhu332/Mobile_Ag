# Automation API inventory (actual implemented routes)

All endpoints below are under `/api/automation`, require the current workbench bearer token and pass existing Host/Origin/body-size middleware. This is **one local operator**, not multi-tenant authorization. Read access to that operator's historical reports is not removed when device execution scope is revoked. No external target endpoints are invented here; target API inventory is imported per run with explicit provenance.

| Endpoint | Method | Purpose / authorization | Inputs / validation | Sensitive data / risk boundary | Verification |
|---|---|---|---|---|---|
| `/capabilities` | GET | Explain supported subset; local operator | None | No credentials; limitations explicit | Wheel authenticated smoke |
| `/runs` | GET | List up to 100 local operator run summaries | None | App IDs/status; no target actions | Auth-negative and browser |
| `/runs` | POST | Observe current scoped Android app; exact device/package + `automation_observe`, server device ceiling | Strict CreateRun: exact component, environment, dedicated confirmations, budgets, optional parent and read-only captures | Initial hierarchy text never stored; no launch/taps; saved capture origins/methods intersect server ceilings | Mocked positive/negative scope; opt-in real fixture |
| `/runs/{rid}` | GET | Read local historical run | Opaque run ID validated; missing 404 | Private redacted state, device/build/configuration metadata | Browser/polling |
| `/runs/{rid}/observe` | POST | Refresh read-only map; observation scope and valid session | Revision, idle/device-lock checks; bounded hierarchy | Outside-package/system UI fails closed; no taps | Scope/locator tests |
| `/runs/{rid}/execute` | POST | Bounded approved navigation/API cases; exact device/package + `automation_execute` | Strict ExecuteRun, run-ID confirmation, CAS revision, known safe exact actions/cases, optional Back/ephemeral header | ADB device-wide TOCTOU guardrail; API origin/method/DNS/TLS checks; credentials not persisted | Duplicate/stale/unsafe/revoked tests, loopback HTTP, browser, real fixture |
| `/runs/{rid}/cancel` | POST | Stop active local run | Active status and CAS flag | Cannot undo an already-issued input; future guards stop | Concurrent cancellation test |
| `/runs/{rid}/captures` | POST | Import/rebind URLs for scoped read-only tests; observation scope | Revision/idle, GET/HEAD only, read-only confirmed, approved origins/methods, max ten; duplicate captures rejected | URLs memory-only, credential-bearing queries rejected; no headers/bodies; no network at import | Router rebind/revoked origin test |
| `/runs/{rid}/report` | GET | Build coverage/report, compare parent assertions | Stored opaque run and parent IDs | Redacted shapes/structural graph; readiness null, classifier never confirms vulnerabilities | Unit/report/browser |
| `/runs/{rid}/export` | GET | Download canonical redacted JSON | Stored opaque ID; safe fixed filename | Same evidence boundaries; browser object URL revoked | Browser/API |
| `/runs/{rid}/screens/{sid}/layout` | GET | Text/pixel-free structural SVG | Screen must belong to stored run; numeric bounds/allowlisted role | Does not capture actual screenshot or confirm contrast/accessibility | Pure SVG/privacy test |

Contract-validation errors are generic 422s and do not echo submitted input/Authorization values. Denied scope is 403; stale/duplicate execution or lost ephemeral targets is 409; missing run/screen is 404. Transport/adapter failures never become clean/pass reports. Body shapes/status observations are not proof of protected-data impact. Backend ownership checks, TLS, session and target authorization **cannot be securely fixed through UI/UX alone**.
