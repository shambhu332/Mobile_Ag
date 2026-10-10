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


def evaluate(corpus: dict) -> dict:
    tp = fp = fn = known_fn = 0
    unexpected_fn = 0
    per_case = []
    engine = TaintEngine()
    for case in corpus["cases"]:
        expected = set(case["expected_cwes"])
        observed = {finding.cwe_id for finding in engine.analyze_source_content(
            case["source"], f"benchmark/{case['id']}.{case['language']}")}
        case_tp, case_fp, case_fn = len(expected & observed), len(observed - expected), len(expected - observed)
        known_misses = set(case.get("known_misses", []))
        case_known_fn = len((expected - observed) & known_misses)
        case_unexpected_fn = case_fn - case_known_fn
        tp += case_tp
        fp += case_fp
        fn += case_fn
        known_fn += case_known_fn
        unexpected_fn += case_unexpected_fn
        per_case.append({"id": case["id"], "expected": sorted(expected), "observed": sorted(observed),
                         "tp": case_tp, "fp": case_fp, "fn": case_fn,
                         "known_fn": case_known_fn, "unexpected_fn": case_unexpected_fn})
    return {
        "benchmark": "synthetic_android_taint_smoke",
        "schema_version": corpus["schema_version"],
        "detector": "TaintEngine (Java AST when available; lexical fallback)",
        "scope_note": corpus["description"],
        "tp": tp, "fp": fp, "fn": fn, "known_fn": known_fn,
        "unexpected_fn": unexpected_fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "cases": per_case,
    }


def main() -> None:
    corpus_path = Path(__file__).resolve().parents[1] / "tests/fixtures/sast_benchmark.json"
    report = evaluate(json.loads(corpus_path.read_text(encoding="utf-8")))
    print(json.dumps(report, indent=2))
    raise SystemExit(1 if report["fp"] or report["unexpected_fn"] else 0)


if __name__ == "__main__":
    main()
