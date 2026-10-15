import json
from pathlib import Path
import runpy


def test_smali_register_flow_benchmark_has_no_smoke_regressions():
    root = Path(__file__).resolve().parents[1]
    corpus = json.loads((root / "tests/fixtures/smali_register_flow_benchmark.json").read_text())
    evaluate = runpy.run_path(str(root / "scripts/evaluate-smali-flow-benchmark.py"))["evaluate"]
    result = evaluate(corpus)
    assert result["tp"] == 4
    assert result["fp"] == 0
    assert result["fn"] == 0
    duplicate_cwe_case = next(case for case in result["cases"] if case["id"] == "two_sink_instances_same_cwe")
    assert duplicate_cwe_case["tp"] == 2
    assert [candidate["sink_line"] for candidate in duplicate_cwe_case["observed"]] == [10, 11]
    assert "Does not measure whole-program or APK recall" in result["scope_note"]
