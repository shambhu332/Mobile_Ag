#!/usr/bin/env python3
"""Evaluate a separate labeled holdout corpus without using it for tuning.

The report is per CWE and language for both automatic and lexical-only
backends. These bounded synthetic fixtures measure only the named analyzer,
not APK-level or field precision/recall.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(os.environ.get("MOBILEAG_SOURCE_ROOT", ROOT)).resolve()))
from mobileag.analysis.taint_engine import TaintEngine


def evaluate(corpus: dict) -> dict:
    coverage: dict[str, dict[str, int]] = {}
    for case in corpus["cases"]:
        row = coverage.setdefault(case["language"], {"cases": 0, "positive_cases": 0, "negative_cases": 0})
        row["cases"] += 1
        row["positive_cases" if case["expected_cwes"] else "negative_cases"] += 1

    def run(use_ast: bool) -> dict:
        engine = TaintEngine()
        if not use_ast:
            engine._java_ast.available = False
        by_cwe: dict[str, dict[str, int]] = {}
        by_language: dict[str, dict[str, int]] = {}
        cases = []
        total = {"tp": 0, "fp": 0, "fn": 0}
        for case in corpus["cases"]:
            observed = {finding.cwe_id for finding in engine.analyze_source_content(
                case["source"], f"holdout/{case['id']}.{case['language']}")}
            expected = set(case["expected_cwes"])
            scores = {"tp": len(expected & observed), "fp": len(observed - expected),
                      "fn": len(expected - observed)}
            for key, count in scores.items():
                total[key] += count
            for cwe in expected | observed:
                by_cwe.setdefault(cwe, {"tp": 0, "fp": 0, "fn": 0})
                counts = by_cwe[cwe]
                counts["tp"] += int(cwe in expected and cwe in observed)
                counts["fp"] += int(cwe not in expected and cwe in observed)
                counts["fn"] += int(cwe in expected and cwe not in observed)
            lang = by_language.setdefault(case["language"], {"tp": 0, "fp": 0, "fn": 0})
            for key, count in scores.items():
                lang[key] += count
            cases.append({"id": case["id"], "language": case["language"],
                          "expected": sorted(expected), "observed": sorted(observed), **scores})

        def rates(groups: dict[str, dict[str, int]]) -> dict[str, dict[str, int | float | None]]:
            return {name: {**row,
                           "precision": row["tp"] / (row["tp"] + row["fp"])
                           if row["tp"] + row["fp"] else None,
                           "recall": row["tp"] / (row["tp"] + row["fn"])
                           if row["tp"] + row["fn"] else None}
                    for name, row in sorted(groups.items())}

        return {"backend": "java_ast_plus_lexical" if engine._java_ast.available else "lexical_fallback",
                **total,
                "precision": total["tp"] / (total["tp"] + total["fp"])
                if total["tp"] + total["fp"] else None,
                "recall": total["tp"] / (total["tp"] + total["fn"])
                if total["tp"] + total["fn"] else None,
                "by_cwe": rates(by_cwe), "by_language": rates(by_language), "cases": cases}

    return {"benchmark": "synthetic_android_taint_heldout", "schema_version": corpus["schema_version"],
            "scope_note": corpus["description"], "case_count": len(corpus["cases"]),
            "fixture_coverage_by_language": coverage,
            "limitations": ["synthetic source snippets only", "CWE/case matching, not finding-instance matching",
                            "no APK packaging, manifest reachability, runtime behavior, or exploitability measured"],
            "backends": {"automatic": run(use_ast=True), "lexical_fallback": run(use_ast=False)}}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path,
                        default=ROOT / "tests/fixtures/sast_holdout.json")
    args = parser.parse_args()
    report = evaluate(json.loads(args.corpus.read_text(encoding="utf-8")))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
