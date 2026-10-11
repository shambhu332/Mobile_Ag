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
    assert result["tp"] == 29  # primitive-only SQL case is a negative control
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert result["known_fn"] == 0
    assert result["unexpected_fn"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    backends = result["backend_results"]
    assert backends["automatic"]["backend"] in {"java_ast_plus_lexical", "lexical_fallback"}
    fallback = backends["lexical_fallback"]
    assert fallback["backend"] == "lexical_fallback"
    # The multiline flow must be found even without the optional parser.
    assert fallback["fn"] == 0
    assert fallback["known_fn"] == 0
    assert fallback["unexpected_fn"] == 0
    assert fallback["recall"] == 1.0
    assert fallback["cases"]
    assert {"CWE-22", "CWE-78", "CWE-470"} <= set(fallback["by_cwe"])
    assert all(metrics["fp"] == 0 and metrics["fn"] == 0
               for metrics in fallback["by_cwe"].values())
