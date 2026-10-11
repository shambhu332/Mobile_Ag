"""Shape and accounting checks for the separate synthetic holdout corpus."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("evaluate_sast_holdout", ROOT / "scripts/evaluate-sast-holdout.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_holdout_corpus_is_separate_paired_and_stratified():
    corpus = json.loads((ROOT / "tests/fixtures/sast_holdout.json").read_text())
    assert len(corpus["cases"]) >= 10
    assert len({case["id"] for case in corpus["cases"]}) == len(corpus["cases"])
    assert any(case["expected_cwes"] for case in corpus["cases"])
    assert any(not case["expected_cwes"] for case in corpus["cases"])
    smoke = json.loads((ROOT / "tests/fixtures/sast_benchmark.json").read_text())
    assert not ({case["id"] for case in corpus["cases"]}
                & {case["id"] for case in smoke["cases"]})

    report = MODULE.evaluate(corpus)
    assert report["case_count"] == len(corpus["cases"])
    assert report["fixture_coverage_by_language"]["java"]["positive_cases"] > 0
    assert report["fixture_coverage_by_language"]["kotlin"]["negative_cases"] > 0
    assert report["limitations"]
    for backend in report["backends"].values():
        assert len(backend["cases"]) == len(corpus["cases"])
        for counts in (backend["by_cwe"].values(), backend["by_language"].values()):
            for group in counts:
                assert group["tp"] + group["fn"] >= 0
                assert group["fp"] >= 0
