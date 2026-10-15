#!/usr/bin/env python3
"""Evaluate bounded local Smali register-flow candidates on synthetic fixtures.

The numbers cover only this labeled smoke corpus, not whole APKs or product
recall. Keep all examples synthetic and preserve negative controls.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mobileag.analysis.call_graph import SmaliCallGraphEngine


def evaluate(corpus: dict) -> dict:
    tp = fp = fn = 0
    cases = []
    for case in corpus["cases"]:
        with tempfile.TemporaryDirectory(prefix="mobileag-smali-bench-") as directory:
            smali_path = Path(directory) / f"{case['id']}.smali"
            smali_path.write_text(case["source"], encoding="utf-8")
            findings = SmaliCallGraphEngine().audit_smali_directory(directory)
        observed = Counter(
            (finding.cwe_id, finding.line_number)
            for finding in findings
            if finding.metadata.get("analysis_kind") == "smali_local_register_flow"
        )
        expected = Counter(
            (candidate["cwe"], candidate["sink_line"])
            for candidate in case["expected_candidates"]
        )
        matched = expected & observed
        case_tp = sum(matched.values())
        case_fp = sum((observed - expected).values())
        case_fn = sum((expected - observed).values())
        tp += case_tp
        fp += case_fp
        fn += case_fn
        cases.append({"id": case["id"],
                      "expected": sorted([{"cwe": cwe, "sink_line": line} for cwe, line in expected.elements()],
                                         key=lambda item: (item["cwe"], item["sink_line"])),
                      "observed": sorted([{"cwe": cwe, "sink_line": line} for cwe, line in observed.elements()],
                                         key=lambda item: (item["cwe"], item["sink_line"])),
                      "tp": case_tp, "fp": case_fp, "fn": case_fn})
    return {
        "benchmark": "synthetic_smali_register_flow_smoke",
        "schema_version": corpus["schema_version"],
        "detector": "SmaliCallGraphEngine local move-result/move-object register pass",
        "scope_note": corpus["description"],
        "tp": tp, "fp": fp, "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "cases": cases,
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    corpus = json.loads((root / "tests/fixtures/smali_register_flow_benchmark.json").read_text(encoding="utf-8"))
    report = evaluate(corpus)
    print(json.dumps(report, indent=2))
    raise SystemExit(1 if report["fp"] or report["fn"] else 0)


if __name__ == "__main__":
    main()
