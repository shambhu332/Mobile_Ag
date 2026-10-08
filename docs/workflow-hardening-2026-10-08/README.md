# Workflow hardening — 2026-10-08

## Scope and preservation

Local MobileAg code and synthetic fixtures only. No live APK, Android device,
external API, Firebase backend or commercial LLM was tested. Existing dirty
work was retained. This is a remediation batch, not completion of every feature
in the five-phase guide. The original remediation sessions did not push or change visibility; publication is a separate step.

## Reproduced baseline

`python -m pytest -q`: 29 failed, 378 passed. Failures included credential
redaction, exported finding status/version, validation-error disclosure,
LLM response accounting, legacy DAST authorization, and one obsolete test that
expected proven UXSS from syntactic call reachability.

## Changes

- Redact additional nested credential/header fields and quoted JSON values;
  extend redaction to generated finding outputs and raw-dictionary SARIF.
- Omit rejected/duplicate SARIF findings, report actual package version, and
  preserve unverified versus analyst-attested proof semantics.
- Return validation errors without rejected input values/context.
- Accept provider token-usage accounting instead of discarding successful SDK responses.
- Bind legacy DAST jobs to the initiating session; recheck session and scope
  before stages. Composite fuzz permission does not grant storage, memory,
  install, provider, deep-link or crawl permissions. Device inventory no longer
  probes root across connected devices; unavailable devices fail explicitly.
- Repair authentication-auditor construction/schema errors; emit unscored lexical
  review candidates rather than signature/pinning/bypass conclusions.
- Disable draft API/Firebase/auth live entrypoints pending proper integration.
  Removed the unscoped fallback, concurrent rate-limit burst, database-root reads,
  bucket listing, anonymous sign-up and device-global secret collection.
- Reuse bounded Android surface review for the WebView facade. A Smali invocation
  does not establish a boolean argument or exploitability.
- Report/checklist templates no longer claim comprehensive/manual/runtime work,
  low risk or MASVS passes merely from absent findings. Redact report metadata
  before formatting. Planning labels are not execution evidence.
- Update the obsolete Smali assertion to require UNVERIFIED, zero automatic CVSS,
  and explicit missing register-dataflow proof; do not inflate analyzer confidence.

## Remaining work / limitations

- The offline authentication/Firebase engines are integrated into static scans; this is still not a fully integrated five-phase dashboard workflow.
- MobSF lifecycle/import, per-fixture authentication/Firebase tests, scoped
  rate-limit execution, and real-device validation still require implementation
  and explicit target approval. Disabled methods raise PermissionError rather
  than claiming success or silently enabling network access.
- Legacy DAST checks are stage-boundary checks; already-running inner operations
  are not guaranteed to stop immediately on revocation.
- Lexical analysis is not exhaustive. No all-language, complete dataflow,
  automatic exploit proof or universal redaction coverage is claimed.
- Existing unrelated edits remain uncommitted; this batch does not certify them.

## Validation

- Final full suite: **422 passed**, 0 failed, 93.93 seconds. Third-party Python
  3.14/pytest-asyncio deprecation warnings remain (19,863 warnings).
- Targeted privacy/provider/DAST suite: 29 passed.
- Draft workflow boundary/report suite: 15 passed.
- `compileall` and `git diff --check`: passed.
- Browser product regression: passed against a real loopback server with synthetic
  fixtures, zero page errors and no off-loopback runtime/API requests.
- Console regression: initial default-browser launch failed because the expected
  Playwright headless-shell binary was absent; retry uses an existing Chromium.
- Tool versions and final console status: see `validation-summary.json`.

Tests establish these local contracts, not ordinary-app exploitation or deployed
backend security. The Smali test change corrects an unsupported proof expectation;
28 baseline failing tests were repaired without weakening their assertions.

## Continuation: bounded offline integration

- Wired real authentication/session lexical review and Firebase configuration
  inventory into the static orchestrator; no live requests are triggered.
- Added shared Linux file-reader bounds: 5,000 examined entries, 2 MiB per file,
  32 MiB total bytes; skip symlinks/nonregular files and avoid implicit cwd scans.
  Final-component reads use O_NOFOLLOW. This is not a claim of general concurrent
  hostile-filesystem containment; production web jobs still need isolation.
- Authentication comments are ignored; findings retain location/rule, not raw
  credential values. Neither password policy nor server token validation is proven.
- Firebase reviews both source and resource directories, returns inventory counts
  rather than extracted configuration values, and labels malformed/skipped/truncated
  analysis partial. Existing lexical URL formats are not an exhaustive SDK inventory.
- Coverage is initialized, propagated through scan state/reports, and marks analyzer
  failures incomplete. Runtime remains not_tested and proof not_proven.
- Validation: combined targeted suite 32 passed; final integration/report suite
  6 passed; full suite 428 passed in 33.07 seconds. Compile/diff checks passed.
  Browser product rerun passed; console retry also passed with the existing Chromium.
- No original APK or live device/backend was assessed, and these local validation results were recorded before publication.

## Publication preparation

The contributor guide and roadmap now describe bounded starter tasks, synthetic
checks, Fish activation and remaining integration work. A fresh pre-publication
run passed 428 tests (29.09 seconds); dashboard asset verification, wheel build
and installed-wheel smoke outside the source checkout passed. The repository
was verified private, and its visibility is not being changed.

Local credential-bearing edits in `.env.example` are excluded from the commit
and preserved in the working tree. They must be rotated and moved to ignored
local configuration. Unrelated screenshot/baseline artifacts are also left local.
A staged-format scan found no full credential formats; that bounded check is not
a guarantee that every possible secret format can be detected.
