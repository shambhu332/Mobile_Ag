import json
import importlib.util
from pathlib import Path

_script = Path(__file__).parents[1] / "scripts/evaluate-sast-benchmark.py"
_spec = importlib.util.spec_from_file_location("evaluate_sast_benchmark", _script)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
evaluate = _module.evaluate


def test_synthetic_taint_smoke_benchmark():
    corpus = json.loads((Path(__file__).parent / "fixtures/sast_benchmark.json").read_text())
    result = evaluate(corpus)
    assert result["tp"] == 23
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert result["known_fn"] == 0
    assert result["unexpected_fn"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
