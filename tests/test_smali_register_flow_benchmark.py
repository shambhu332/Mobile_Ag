import json
from pathlib import Path
import runpy


def test_smali_register_flow_benchmark_has_no_smoke_regressions():
    root = Path(__file__).resolve().parents[1]
    corpus = json.loads((root / "tests/fixtures/smali_register_flow_benchmark.json").read_text())
    evaluate = runpy.run_path(str(root / "scripts/evaluate-smali-flow-benchmark.py"))["evaluate"]
    result = evaluate(corpus)
    assert result["tp"] == 10
    assert result["fp"] == 0
    assert result["fn"] == 0
    cursor_case = next(case for case in result["cases"]
                       if case["id"] == "contentresolver_cursor_value_to_webview")
    assert cursor_case["tp"] == 1
    external_content_case = next(case for case in result["cases"]
                                 if case["id"] == "tainted_path_files_readstring_to_webview")
    assert external_content_case["tp"] == 1
    lifecycle_case = next(case for case in result["cases"]
                         if case["id"] == "lifecycle_intent_action_to_webview")
    assert lifecycle_case["tp"] == 1
    activity_result_case = next(case for case in result["cases"]
                                if case["id"] == "activity_result_intent_data_to_webview")
    assert activity_result_case["tp"] == 1
    lifecycle_extra_case = next(case for case in result["cases"]
                               if case["id"] == "lifecycle_intent_extra_to_webview")
    assert lifecycle_extra_case["tp"] == 1
    for negative_id in ("hardcoded_content_uri_is_not_tainted", "hardcoded_path_is_not_tainted",
                       "locally_constructed_intent_data_is_not_tainted",
                       "local_intent_extra_is_not_tainted",
                       "same_named_callback_wrong_superclass_is_not_a_root",
                       "ordinary_intent_parameter_helper_is_not_a_lifecycle_root"):
        negative_case = next(case for case in result["cases"] if case["id"] == negative_id)
        assert negative_case["observed"] == []
    duplicate_cwe_case = next(case for case in result["cases"] if case["id"] == "two_sink_instances_same_cwe")
    assert duplicate_cwe_case["tp"] == 2
    assert [candidate["sink_line"] for candidate in duplicate_cwe_case["observed"]] == [10, 11]
    branch_case = next(case for case in result["cases"] if case["id"] == "conditional_branch_target_reachable_sink")
    assert branch_case["tp"] == 1
    assert "not blind, independent, whole-program, or APK-recall evidence" in result["scope_note"]
