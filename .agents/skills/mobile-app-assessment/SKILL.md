---
name: mobile-app-assessment
description: >-
  Plan and perform authorized Android application security assessments with
  MobileAg. Use for APK scope review, static triage, explicit device/API testing,
  validation of IPC, URI, file, storage, logging, WebView and pending-intent
  risks, or evidence-based reporting. Do not use to infer authorization or
  initiate tests against an unspecified target.
---

# Mobile application assessment (MobileAg)

Use MobileAg's existing isolation, exact-scope and evidence contracts. The skill
is guidance, not authorization, a scanner, or proof that a test ran. Do not
weaken application controls to make a test pass.

## Start safely

1. Establish written authorization for the exact APK/version, package, API
   origins, device serial, accounts, dates, permitted actions, exclusions and
   reporting route. If any live-test boundary is unclear, stay offline/static
   and ask the owner; do not infer scope from APK strings, discovered URLs, or
   connected devices.
2. Use synthetic data and researcher-controlled accounts. Prefer a fresh copy
   of the original artifact; preserve it and record SHA-256, size, filename,
   package/version, source, tool versions and relevant OS build. Never overwrite
   the source artifact or silently patch/re-sign it.
3. Start with `python -m mobileag.cli scan --apk <owned.apk> --offline --output <new-output-dir>`.
   Offline static analysis must not contact a target, provider, or vulnerability
   database. Treat parser/decompiler errors, unsupported formats and partial
   output as coverage gaps—not clean results. Keep JADX/apktool output tied to
   the original APK hash and note decompilation uncertainty.
4. For live tests use the Guided Assessment UI or the current documented CLI
   workflow. Configure exact `MOBILEAG_ALLOWED_DEVICES` and
   `MOBILEAG_ALLOWED_ORIGINS` ceilings, select the authorized device explicitly,
   and approve each exact stage/scope in the application. No implicit device,
   install replacement, permission grant, root/SSL bypass, arbitrary shell, or
   broad API replay. Read `.agents/skills/mobileag-pipeline/SKILL.md` and the
   current guided-assessment docs before using dynamic stages.

## Review Android attack surfaces

Follow attacker-controlled values from their real entry point to a security-
sensitive sink. Record both the source and sink, guards, caller identity, app
state, and practical attacker prerequisites. Review only when relevant:

- **Manifest/IPC:** exported activities, services, receivers and providers;
  permission protection, component-level authorization, caller validation,
  intent extras/ClipData, mutable or unsafe PendingIntents, task/navigation
  assumptions, and confused-deputy paths.
- **Serialization:** Parcelable/Serializable, Bundles, JSON/protobuf or custom
  parsers; untrusted nested/deep input, type confusion, unsafe object creation,
  resource exhaustion and parser failures. Do not label deserialization
  dangerous without a reachable unsafe operation and impact.
- **Files/URIs:** attacker-controlled path segments, canonicalization and
  symlink/race issues, temporary files, archive extraction, path traversal,
  FileProvider roots, URI permission flags/grants, persistable grants and
  cross-app exposure. Distinguish a local-only path issue from a reachable
  disclosure/write primitive.
- **Storage/backup/logging:** sensitive data in preferences, databases, files,
  caches, clipboard, backups or logs; identify the data, storage protection,
  backup behavior, and which attacker can read it. Never collect real user
  data or persist secrets in notes.
- **WebView:** JavaScript and file/content access settings, mixed content,
  `addJavascriptInterface`, navigation/redirect handling, origin validation,
  message channels, SSL error behavior and untrusted content sources. Trace
  control over the URL/content and the bridge's exposed operations.
- **Other boundaries:** authentication/session checks, crypto/key use, network
  trust, native/JNI boundaries and app links/deep links. Include backend/API
  behavior only for exact authorized origins and methods.

A suspicious API call, manifest attribute, decompiler string, or test tool output
is an investigation lead. Confirm reachability and security impact. Static
heuristics are candidates, not verdicts.

## Record coverage without implying completeness

For each relevant area, record one state and a short reason/evidence reference:

| Area | State | What to record |
|---|---|---|
| Manifest and IPC | `not_tested`, `candidate`, `observed`, `attested`, `independently_verified` | Component and method, effective export/permission boundary, caller/input, guard and sink. |
| Serialization | same states | Reachable parser, input limits/type checks, failure behavior and any sensitive operation. |
| Files, content providers and URI grants | same states | Canonical path/root, grant flags/lifetime, caller and demonstrated read/write scope. |
| Storage, backup and logs | same states | Data class, location/protection, backup configuration and which principal could read it. |
| WebView and app links | same states | Content/origin control, navigation policy, bridge surface and observed boundary behavior. |
| Network, API and authentication | same states | Exact authorized origin/method, account role, request/response evidence and oracle limitations. |
| Crypto, native and other boundaries | same states | Key/trust boundary, reachable operation, platform/build and tool/decompiler limits. |

`not_tested` is a gap, not a pass. `candidate` is a lead, `observed` is a
bounded runtime observation, and `attested` is a human-reviewed record.
`independently_verified` requires independent reproduction for the exact artifact
and scope; do not derive it from scanner output, a completed stage, or an
analyst-entered status. Mark non-applicable areas with a reason rather than
silently omitting them. The dashboard's guided-stage coverage ledger describes
what stages actually ran; it is not a substitute for this per-surface review or
an exhaustive MASVS/compliance claim.

## Dynamic validation gates

- Before touching a device, record its serial, OS build, ABI, app package/version,
  install state, test-account class and exact approved operation. Confirm the
  installed artifact matches the preserved hash/package. Keep device-wide
  effects isolated to a dedicated researcher-controlled device.
- Do not treat root/shell access, Frida hooks, authorization-changing patches,
  certificate-bypass behavior, or an old-OS-only reproduction as proof of an
  ordinary-app exploit on a current device. Report such results as modified-lab
  observations with their limits.
- Use a positive control, a negative control and synthetic data. Stop if the
  app/device identity or saved scope differs, the test would mutate real data,
  a redirect leaves the approved origin, or the observed behavior exceeds the
  approved action. Avoid destructive, high-volume, brute-force or persistence
  testing unless separately authorized and bounded.
- A crash is evidence of a crash only. Record exact logs and target process
  attribution; shared logcat output without the target package and PID is not
  target evidence. Preserve redacted raw evidence and do not claim impact not
  seen in the controlled test.

## Report findings honestly

For each actionable issue state:

- precise APK/review location (file/class/method/line or smali/native offset),
  artifact hash and version; include decompiler/tool limitations;
- attacker-controlled input, entry point, validation/authorization checks and
  sensitive sink;
- attacker prerequisites, demonstrated impact using synthetic data, and exact
  reproducible steps;
- observed platform/device OS build, ABI, app state, controls and result;
- evidence state: static candidate, runtime observation, analyst attestation, or
  independently verified exploit. Do not conflate them;
- concrete remediation at the correct trust boundary, plus meaningful regression
  test and negative control.

Do not invent severity, CVSS, program eligibility, framework compliance, clean
status, or runtime coverage. If impact or reachability is not shown, report an
investigation lead with the next safe validation step instead of a confirmed
vulnerability.

## MobileAg references

- `.agents/skills/mobileag-pipeline/SKILL.md` — supported workflows and safety
  gates.
- `docs/guided-assessment-2026-10-06/README.md` — assessment stages and scope.
- `docs/product-security-review-2026-10-05/TRANSFORMATION_STATUS.md` — known
  execution and proof boundaries; verify its applicability to the current
  checkout.
