import json
from pathlib import Path
import runpy


def test_smali_register_flow_benchmark_has_no_smoke_regressions():
    root = Path(__file__).resolve().parents[1]
    corpus = json.loads((root / "tests/fixtures/smali_register_flow_benchmark.json").read_text())
    evaluate = runpy.run_path(str(root / "scripts/evaluate-smali-flow-benchmark.py"))["evaluate"]
    result = evaluate(corpus)
    assert result["tp"] == 2
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert "Does not measure whole-program or APK recall" in result["scope_note"]
