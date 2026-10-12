# External mobile-security skill review (2026-10-11)

## Scope and evidence

Reviewed the public repository `mukul975/Anthropic-Cybersecurity-Skills` at
commit `54a798831d2266a3ca61ce68a7acb80b81160d57`, including its README,
`conducting-mobile-app-penetration-test/SKILL.md`, API reference and agent
script, plus related Android intent, static-analysis, dynamic-analysis, API-auth
and storage skills. No script was run and no external app/device/API was tested.
The supplied GetClaudeSkills listing was reviewed as a third-party catalog
summary; its direct page was not independently fetchable through this session,
so catalog-only details are not treated as source-code evidence.

This was a targeted security/fit review, not a complete audit of all 817+
skills or the upstream repository. Upstream README values are internally
inconsistent (817/818 skill counts and 29/34 domains); counts are publisher
claims, not independently reproduced metrics.

## What is reusable for MobileAg

1. **Progressive disclosure and skill routing.** A small discoverable skill
   entry point plus task-specific checklists supports reuse without loading a
   broad security encyclopedia. Adapted into
   `.agents/skills/mobile-app-assessment/SKILL.md`.
2. **Lifecycle structure.** Scope and prerequisites → static analysis →
   network/storage/platform review → runtime validation → report is a useful
   mental model. Keep MobileAg's explicit upload, exact-scope, stage selection,
   approval and evidence lifecycle as the actual execution boundary.
3. **Coverage organization.** A mobile checklist grouped by storage, network,
   authentication, IPC/platform, WebView, cryptography and resilience can
   improve coverage tracking, provided each row has `not tested / candidate /
   observed / attested / independently verified` semantics and no category
   implies a clean result.
4. **Verification discipline.** Require source → guard → sink traces, positive
   and negative controls, exact artifact/device/version binding, concrete impact,
   and limitations before escalation. This strengthens MobileAg's existing
   evidence contract rather than replacing it.
5. **Report shape.** Preserve finding location, prerequisites, steps, impact,
   remediation and platform context. MobileAg should additionally preserve the
   original APK hash, OS build/ABI, tool/decompiler limitations and evidence
   class.

## What should not be imported as executable workflow

The upstream skill's prose recommends broad certificate-pinning/root-detection
bypass, authentication callback hooks, forced runtime manipulation, direct
private app-directory access and modified/re-signed apps. Those may be separate
lab objectives only with explicit authorization and isolation; they are not
ordinary-app exploit proof and must not be default test stages.

The adjacent `scripts/agent.py` is not a safe MobileAg agent and was not copied
or executed. Static review found concrete problems:

- `requests.get(..., verify=False)` is used for both API and certificate tests;
  the latter does not configure a proxy and a successful direct HTTP response
  cannot prove pinning is absent.
- `--api-url` accepts an arbitrary base URL and immediately performs requests
  to guessed paths, authenticated and unauthenticated, with no origin allowlist,
  redirect policy or exact per-route approval. This creates unintended-target
  and SSRF-like risks if used in a server context.
- The storage check invokes ADB without a selected serial and hardcodes
  `com.target.app`; it does not bind observations to the declared APK/package.
  `run-as` success is conditional on app/debug build state and does not prove
  ordinary-app access.
- Manifest substring checks overstate `exported=true`, `allowBackup=true` and
  missing custom network security config as findings without effective SDK,
  permission, caller, OS-version or platform-default analysis.
- `extract_strings_from_apk` is keyword matching, not secret validation; the
  script reports only counts, while its name/description can imply verified
  exposed credentials.
- The CLI accepts `--apk` but does not call its `decompile_apk` helper; the
  documented workflow and actual run differ. There are no recorded safe-device
  gates, evidence controls, artifact binding or report limitations.

These are code-review conclusions about the inspected upstream commit, not
claims about any deployment or later version.

## GetClaudeSkills listing

The listing identifies the same named mobile pentest skill, author/repository,
installation methods and a high-level MASTG/static/runtime/API scope. These are
catalog metadata and a summary of upstream content, not independent technical
validation. The repository itself is the primary evidence for the implementation
review. Ratings, views, stars, marketplace labels and update dates are not
security quality evidence.

## MobileAg adaptation made

Created a repo-scoped `mobile-app-assessment` skill focused on authorized
Android review and MobileAg's gates. It reuses general workflow organization,
not upstream code, claims or unsafe commands. It requires preservation,
explicit target scope, synthetic data, caller/source-to-sink reasoning, distinct
evidence states and reportable uncertainty. Existing `mobileag-pipeline` skill
remains the authority for how to operate the current product.

## Future additions (recommendations, not implemented here)

- Add an Android/MASVS coverage ledger to assessment reports with explicit
  evidence state, evidence references, test platform/build and a gap reason.
- Add optional static review checklists for exported IPC/providers, PendingIntent
  mutability, URI grants/FileProvider roots, deserialization, backup/logging and
  WebView bridges, each linking to the exact source-to-sink evidence.
- Add a scope preview that shows selected stages, approved package, device serial,
  API origins/methods and actions before approval; retain no credentials in it.
- Add no new autonomous pentest agent until every operation has exact server-side
  authorization, no free-form URL/device selection, bounded requests, no
  authorization bypass by the agent, reproducible positive/negative controls,
  and a reviewable evidence record. An advisory workflow skill is safer and more
  useful than importing the upstream network/device script.
