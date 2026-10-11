#!/usr/bin/env python3
"""Run the committed synthetic SAST benchmark and print JSON metrics.

Metrics are case/CWE-level for the named detector only; this is not a product
recall claim. Keep the benchmark artifact synthetic and versioned.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mobileag.analysis.taint_engine import TaintEngine


def _evaluate_backend(corpus: dict, *, use_ast: bool | None) -> dict:
    tp = fp = fn = known_fn = 0
    unexpected_fn = 0
    per_case = []
    by_cwe: dict[str, dict[str, int]] = {}
    by_language: dict[str, dict[str, int]] = {}
    fixture_coverage: dict[str, dict[str, int]] = {}
    engine = TaintEngine()
    if use_ast is False:
        # Exercise the supported lexical fallback even when the optional parser
        # is installed, so benchmark results do not depend on the host setup.
        engine._java_ast.available = False
    backend = ("java_ast_plus_lexical" if engine._java_ast.available
               else "lexical_fallback")
    for case in corpus["cases"]:
        language = case.get("language", "unknown")
        fixture = fixture_coverage.setdefault(language, {"cases": 0, "positive_cases": 0, "negative_cases": 0})
        fixture["cases"] += 1
        fixture["positive_cases" if case["expected_cwes"] else "negative_cases"] += 1
        expected = set(case["expected_cwes"])
        observed = {finding.cwe_id for finding in engine.analyze_source_content(
            case["source"], f"benchmark/{case['id']}.{case['language']}")}
        case_tp, case_fp, case_fn = len(expected & observed), len(observed - expected), len(expected - observed)
        known_misses = set(case.get("known_misses", []))
        case_known_fn = len((expected - observed) & known_misses)
        case_unexpected_fn = case_fn - case_known_fn
        for cwe in expected | observed:
            counts = by_cwe.setdefault(cwe, {"tp": 0, "fp": 0, "fn": 0})
            counts["tp"] += int(cwe in expected and cwe in observed)
            counts["fp"] += int(cwe not in expected and cwe in observed)
            counts["fn"] += int(cwe in expected and cwe not in observed)
        language_counts = by_language.setdefault(language, {"tp": 0, "fp": 0, "fn": 0})
        language_counts["tp"] += case_tp
        language_counts["fp"] += case_fp
        language_counts["fn"] += case_fn
        tp += case_tp
        fp += case_fp
        fn += case_fn
        known_fn += case_known_fn
        unexpected_fn += case_unexpected_fn
        per_case.append({"id": case["id"], "expected": sorted(expected), "observed": sorted(observed),
                         "tp": case_tp, "fp": case_fp, "fn": case_fn,
                         "known_fn": case_known_fn, "unexpected_fn": case_unexpected_fn})
    cwe_metrics = {
        cwe: {**counts,
              "precision": counts["tp"] / (counts["tp"] + counts["fp"])
              if counts["tp"] + counts["fp"] else None,
              "recall": counts["tp"] / (counts["tp"] + counts["fn"])
              if counts["tp"] + counts["fn"] else None}
        for cwe, counts in sorted(by_cwe.items())
    }
    return {
        "benchmark": "synthetic_android_taint_smoke",
        "schema_version": corpus["schema_version"],
        "detector": "TaintEngine",
        "backend": backend,
        "scope_note": corpus["description"],
        "tp": tp, "fp": fp, "fn": fn, "known_fn": known_fn,
        "unexpected_fn": unexpected_fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "by_cwe": cwe_metrics,
        "by_language": {
            language: {**counts,
                       "precision": counts["tp"] / (counts["tp"] + counts["fp"])
                       if counts["tp"] + counts["fp"] else None,
                       "recall": counts["tp"] / (counts["tp"] + counts["fn"])
                       if counts["tp"] + counts["fn"] else None}
            for language, counts in sorted(by_language.items())
        },
        "fixture_coverage_by_language": fixture_coverage,
        "cases": per_case,
    }


def evaluate(corpus: dict) -> dict:
    """Report automatic-host behavior and a deterministic lexical-only run.

    The lexical result matters even on machines with Tree-sitter installed:
    deployments without the optional extra otherwise silently have different
    coverage. Top-level metrics preserve the historical auto-mode API.
    """
    automatic = _evaluate_backend(corpus, use_ast=None)
    lexical = _evaluate_backend(corpus, use_ast=False)
    automatic["backend_results"] = {
        "automatic": {k: v for k, v in automatic.items() if k != "backend_results"},
        "lexical_fallback": lexical,
    }
    return automatic


def main() -> None:
    corpus_path = Path(__file__).resolve().parents[1] / "tests/fixtures/sast_benchmark.json"
    report = evaluate(json.loads(corpus_path.read_text(encoding="utf-8")))
    print(json.dumps(report, indent=2))
    backend_runs = report["backend_results"].values()
    raise SystemExit(1 if any(run["fp"] or run["unexpected_fn"] for run in backend_runs) else 0)


if __name__ == "__main__":
    main()
