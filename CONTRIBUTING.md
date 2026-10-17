# Contributing to MobileAg

Thanks for helping improve MobileAg. Useful contributions include clearer setup
documentation, accessible interface improvements, synthetic regression fixtures,
and narrowly scoped analysis fixes. You do not need a device or a model API key to
work on the mocked regression suite.

If this repository is private, participation requires access granted by its
owner. These instructions do not change its visibility or access controls.

## Before you start

- Check existing issues and pull requests. For a substantial change, describe the
  problem and proposed scope before implementation.
- Work on a branch in your fork, where repository policy permits, or a branch in
  a checkout you are authorized to use. Keep unrelated changes separate.
- Use only synthetic fixtures, researcher-controlled accounts and explicitly
  authorized targets. Do not upload confidential APKs, customer records, session
  tokens, API keys, or `.env` files to issues, pull requests, or test artifacts.
- Report suspected sensitive security issues through an existing trusted private
  channel to the repository owner to agree a disclosure route. Do not publish
  exploit details or secrets in a public issue.

**License note:** there is currently no root-level project license. Bundled
third-party license notices apply to those dependencies, not to MobileAg as a
whole. Ask the repository owner to clarify project licensing and contribution
terms; do not assume an open-source license has been selected.

## Set up a development environment

Python 3.11+ is declared in `pyproject.toml`; CI currently uses Python 3.14. The
constraint file below is a Linux Python 3.14 validation snapshot, not a guarantee
for every Python version or platform.

From your checkout, using Python 3.14 to match CI:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -c requirements/validated-python314.txt -e '.[test]'
```

For Fish, activate with `source .venv/bin/activate.fish` instead.
Keep API keys in an ignored local `.env` or a secret manager; never populate
the tracked `.env.example` with real credentials.

Start the local API when needed:

```bash
[ -f .env ] || cp .env.example .env
python -m mobileag.cli web --host 127.0.0.1 --port 8080
```

Set a researcher-managed `MOBILEAG_API_TOKEN` for bearer authentication. Never put it in URLs, screenshots, or reports. Leave device and outbound target scope empty unless your
task explicitly requires approved live testing. Missing isolation prerequisites
must fail closed; do not disable safeguards to make a scan run. See the
[README](README.md#quick-start) for sandbox, decompiler and optional device setup.

## Run the checks

Run from the checkout with the development environment active:

```bash
python -m pytest -q
python -m build --wheel
git diff --check
```

Record exact commands and results in your pull request, including any failures or
checks you could not run. If you suspect a pre-existing failure, compare against
the base revision in a separate checkout instead of weakening the test.

### API changes

The browser UI has been removed; validate authenticated API routes and CLI behavior instead.

## Find your way around

| Area | Location | Useful contribution examples |
| --- | --- | --- |
| Static review | `mobileag/analysis/`, `mobileag/ingestion/` | Small synthetic fixtures and false-positive controls |
| API | `mobileag/web/` | Authentication, scope, request validation, persistence and evidence contracts |
| Guided workflows | `mobileag/assessments/` | Explicit approval and cancellation regressions |
| Reports | `mobileag/reporting/` | Clear evidence status and export regressions |
| Tests | `tests/` | Deterministic, isolated tests without live credentials or devices |
| Documentation | `README.md`, `docs/` | Reproducible setup and clearly labelled limitations |

Historical architecture and audit documents describe their recorded revisions.
Check current code, tests and README before treating an older capability claim as
current behavior.

## What makes a good pull request

- Explain the user problem, change and verification; link a relevant issue.
- Add a focused regression for a bug fix, including negative controls where
  authorization, parsing, evidence, or egress is involved.
- Preserve upload-versus-execution separation, explicit scope/approval, offline
  static workers, and server-side authorization. Hiding a UI control is not an
  authorization check.
- Keep static candidates, runtime observations, analyst attestations and proven
  vulnerabilities distinct. Root/shell access or mocked tests do not establish
  ordinary-app exploitability.
- Describe remaining limitations. Do not add fake metrics, unsupported security
  claims, or test-success claims without results.

Small, well-explained contributions are easier to review than unrelated changes
bundled together. Be respectful, assume good intent, and discuss the code rather
than the person.

## Offline workflow starter checks

The authentication/session and Firebase engines now run as bounded offline
reviews in static scans. They do not contact discovered backends or prove an
authentication bypass. Start with these synthetic regression tests:

```bash
python -m pytest -q tests/test_offline_workflow_integration.py \
  tests/test_workflow_draft_boundaries.py tests/test_confirmation_evidence.py
```

Useful small contributions include a positive fixture, a negative fixture, and
explicit partial/error coverage for one parser behavior. Preserve file/byte
limits, credential redaction, zero automatically assigned CVSS for lexical
leads, and `runtime_status=not_tested` unless a test actually ran.

See [workflow hardening and remaining gaps](docs/workflow-hardening-2026-10-08/README.md).
Live integrations need a separate design review with exact fixture scope,
request budgets, revocation checks and synthetic evidence; do not enable the
disabled draft APIs merely to make a feature appear complete.
