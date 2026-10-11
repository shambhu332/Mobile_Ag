# SAST benchmark and coverage reporting (2026-10-11)

## Scope and caveats

`tests/fixtures/sast_holdout.json` is a separate, synthetic development corpus spanning source-to-sink, Android surface, and manifest cases. It is a **development holdout**, not a blinded or independently collected benchmark: fixtures were authored after recent analyzer work and intentionally span those feature areas. Do not use its score as field accuracy or claim whole-APK recall. It measures CWE-per-case behavior, not instance-level matching, manifest reachability, or exploitability.

Run the existing smoke corpus and the holdout separately:

```bash
python scripts/evaluate-sast-benchmark.py
python scripts/evaluate-sast-holdout.py
```

Both reports include automatic and lexical-only backends, per-CWE/per-language metrics, and fixture counts by language. Holdout results are informational; the evaluator does not fail merely because it records a miss. Preserve misses and inspect false positives before changing the detector.

## Recorded comparison

Using the same holdout with the parser environment available, compare baseline `b8ccdaf` with analyzer revision `764825e`:

| Revision | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| `b8ccdaf` | 3 | 0 | 2 | 1.00 | 0.60 |
| `764825e` | 4 | 0 | 1 | 1.00 | 0.80 |

The recovered case is `java_float_extra_to_sql_concat` (a modeled typed `Intent` extra reaching dynamic SQL). The remaining miss is `kotlin_data_string_to_webview` (nullable Intent `dataString` property flow). All five negative controls remained unflagged in these runs. The apparent perfect precision is based on only five negatives and should not be generalized.

Reproduce the baseline comparison in a disposable worktree (do not modify the checkout):

```bash
git worktree add --detach /tmp/mobileag-baseline b8ccdaf
MOBILEAG_SOURCE_ROOT=/tmp/mobileag-baseline python scripts/evaluate-sast-holdout.py
git worktree remove /tmp/mobileag-baseline
```

The evaluator and corpus remain in the current checkout; `MOBILEAG_SOURCE_ROOT` selects the analyzer implementation under test. Use the same environment for both runs because optional AST availability changes the automatic backend. The evaluator also reports lexical-only behavior explicitly.

## Coverage reporting

Report generation now treats `exhaustive: false` and `limits_reached: true` as recorded coverage gaps, not as clean completion. JSON and Markdown include counts and paths for non-exhaustive analyses and reached limits. Static candidate coverage, runtime testing, and exploit proof remain separate claims; no output is an assurance of completeness.

## Next benchmark work

- Add an independently reviewed corpus from authorized artifacts and retain a blind/held-back partition.
- Match findings by normalized location and dataflow instance, not only CWE-per-case.
- Expand Android component, provider, WebView, native, obfuscated, split-APK, and multi-DEX coverage.
- Report skipped files, parser/decompiler failures, tool versions, hashes, and bounded inventory for every run.

## Follow-up shared modeling and Android-surface checks

The shared taint model now recognizes Kotlin inferred simple `Intent` aliases and
`data`/`dataString` properties, while Java AST source typing now requires the
exact framework type `Intent` (qualified names and generics remain accepted).
This fixes a holdout false positive where a user-defined `FakeIntent` class had
been accepted because its name ended in `Intent`.

On the same expanded synthetic holdout (six CWE-positive taint cases, seven
negative cases), revision `eb99357` scored automatic TP=4, FP=1, FN=2 and
lexical TP=4, FP=0, FN=2. The working analyzer scored automatic TP=6, FP=0,
FN=0 and lexical TP=6, FP=0, FN=0. The two misses were Kotlin dataString source
flows; the prior AST-only false positive was the custom lookalike type. These
results are small-corpus development evidence only, not general accuracy.

Android surface review now reports explicit WebView remote-debugging enabled
and Safe Browsing disabled configuration calls as unverified review candidates.
Each has true/false and comment/string controls. On four separately labeled
synthetic Android cases (two positives, two negatives), the prior analyzer
scored TP=0, FP=0, FN=2; the updated analyzer scored TP=2, FP=0, FN=0. Results
remain lexical configuration observations: build variant, API behavior,
content exposure, reachability, and impact are not established. All generated
findings stay INFO/UNVERIFIED with no exploit proof.


## Manifest analysis false-positive control

Manifest review now reports a weak custom permission only when an exported
component actually uses that declared permission. A FileProvider-like component
with an explicit component permission is not reported as unprotected solely
because it is exported. On four synthetic manifest controls (two expected rule
hits and two negatives), baseline `8b43176` scored TP=2/FP=2/FN=0; the updated
review scored TP=2/FP=0/FN=0. This validates only these manifest heuristics, not
merged-manifest correctness, provider path exposure, permission inheritance in
all Android configurations, or ordinary-app exploitability.
