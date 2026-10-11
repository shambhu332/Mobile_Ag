# Accuracy foundations — implementation status

This batch improves the existing pipeline, not the number of agents. It does **not** complete the full accuracy roadmap.

## Implemented

- Location-aware synthetic evaluation with TP/FP/FN, duplicate and execution-error accounting, corpus/source hashes, and exact-source overlap checks.
- Conservative guided coverage ledger: execution, operator-declared authentication, observed device metadata, and independently verified coverage remain separate.
- Export evidence contract: unsupported CONFIRMED claims become UNVERIFIED in reports without changing stored triage. Valid confirmation records remain analyst attestations, not independent exploit verification.
- Structured static source/sink metadata, explicitly unresolved guards and runtime verification.
- Narrow Java primitive-only SQL concatenation suppression. Numeric smoke/holdout labels were corrected; the public holdout is no longer described as blind.
- Offline, scoped comparison of operator-imported synthetic paired-account captures. Positive/negative controls compare exact JSON marker values. Only reduced results are persisted; no requests are sent and identities are not independently verified.
- Retest language distinguishes an assertion now passing from a verified root-cause fix. Dashboard scores no longer invent an 8.8 fallback.

## Validation

Local validation on 2026-10-11:

- Full pytest suite: **565 passed** (27,891 warnings remain).
- Location-aware corpus: **2 TP, 0 FP, 0 FN, 0 failed cases** in each of AST and lexical modes. These six small source fixtures are candidate-flow regressions, not a real-world accuracy estimate or exploit benchmark.
- Isolated Playwright renderer regression: passed; no browser errors.
- Python compilation, dashboard asset validation, and git whitespace checks: passed.
- Changed-file credential-pattern scan: no matches; this is not a guarantee of secret absence.

Reproduce:

```bash
python -m pytest -q
python scripts/evaluate-accuracy.py --corpus tests/fixtures/accuracy_instances.json
python scripts/evaluate-accuracy.py --corpus tests/fixtures/accuracy_instances.json --lexical-only
python scripts/verify-dashboard-assets.py
python tests/browser_accuracy_regression.py --chromium /path/to/chrome
```

## Remaining work

A truly blind external corpus, comprehensive interprocedural/guard reasoning, deeper Android validator families, authenticated role/workflow coverage, controlled live paired-account execution, independent artifact-bound runtime proof, root-cause deduplication, and broader native/iOS analysis remain incomplete. The export evidence gate is not a claim that every raw/live UI ingestion path has been normalized. No live application, device, API target, or model provider was tested in this batch.
