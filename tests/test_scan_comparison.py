import pytest
import importlib
from fastapi.testclient import TestClient
from mobileag.web.repository import ScanRepository

from mobileag.reporting.scan_comparison import compare_scans


def scan(scan_id, findings, digest):
    return {"scan_id": scan_id, "status": "completed", "package_name": "org.example.app",
            "artifact_sha256": digest, "findings": findings}


def finding(path, line, *, method="TaintEngine", cwe="CWE-829", status="UNVERIFIED"):
    return {"id": f"finding-{path}-{line}", "detection_method": method, "cwe_id": cwe,
            "file_path": path, "line_number": line, "status": status,
            "validation_evidence": {"active": True, "secret": "must-not-leak"}}


def test_compare_scans_links_artifacts_and_never_infers_fixed_status():
    baseline = scan("before", [finding("src/A.java", 12), finding("src/B.java", 8)], "a" * 64)
    current = scan("after", [finding("src/A.java", 12, status="CONFIRMED"),
                              finding("src/C.java", 17)], "b" * 64)
    result = compare_scans(baseline, current)
    assert result["relation"] == {"baseline_scan_id": "before", "current_scan_id": "after",
        "package_name": "org.example.app", "baseline_artifact_sha256": "a" * 64,
        "current_artifact_sha256": "b" * 64, "artifact_changed": True,
        "artifact_comparison_status": "changed"}
    states = {row["file"]: row["comparison"] for row in result["comparisons"]}
    assert states == {"src/A.java": "observed_in_both", "src/B.java": "not_observed_in_current",
                      "src/C.java": "new_in_current"}
    assert result["fixed_count"] is None
    assert all("secret" not in str(row) for row in result["comparisons"])


@pytest.mark.parametrize("baseline,current", [
    (scan("running", [], "a"), scan("done", [], "b")),
    (scan("before", [], "a"), {**scan("after", [], "b"), "package_name": "org.other"}),
])
def test_scan_comparison_rejects_incomplete_or_different_package(baseline, current):
    if baseline["scan_id"] == "running":
        baseline["status"] = "running"
    with pytest.raises(ValueError):
        compare_scans(baseline, current)


def test_scan_comparison_counts_unmatchable_locations_and_rejects_path_escape():
    result = compare_scans(scan("before", [finding("../private.java", 4),
                                              finding("src/../../outside.java", 5),
                                              {"cwe_id": "CWE-1"}], "a"),
                           scan("after", [], "b"))
    assert result["unmatchable"] == {"baseline_count": 3, "current_count": 0,
                                     "status": "incomplete_if_nonzero"}
    assert result["comparisons"] == []


def test_scan_comparison_prefers_stable_check_ids_over_detector_names():
    before_finding = finding("src/A.java", 12)
    before_finding["metadata"] = {"check_id": "webview_origin_review"}
    after_finding = finding("src/A.java", 12)
    after_finding["metadata"] = {"check_id": "webview_debugging_review"}
    result = compare_scans(scan("before", [before_finding], "a"),
                           scan("after", [after_finding], "b"))
    assert {(row["rule_id"], row["comparison"]) for row in result["comparisons"]} == {
        ("webview_origin_review", "not_observed_in_current"),
        ("webview_debugging_review", "new_in_current"),
    }


def test_scan_comparison_emits_only_ambiguous_safe_possible_file_move_lead():
    def traced(path, line, operation="WebView.loadUrl", method="com.example.Route#route(android.content.Intent)"):
        item = finding(path, line)
        item["rule_id"] = "webview_input_review"
        item["metadata"] = {"source_sink_trace": {"sink": {
            "operation": operation, "line": line,
            "source_qualified_method_identity": method,
        }}}
        return item

    before = scan("before", [traced("src/OldRoute.java", 12)], "a" * 64)
    after = scan("after", [traced("src/new/Route.java", 34)], "b" * 64)
    result = compare_scans(before, after)
    assert len(result["relocation_leads"]) == 1
    lead = result["relocation_leads"][0]
    assert (lead["baseline_file"], lead["current_file"], lead["baseline_line"], lead["current_line"]) == (
        "src/OldRoute.java", "src/new/Route.java", 12, 34)
    assert lead["interpretation"] == "possible_file_move_manual_review_only_not_a_match_or_fix"
    assert {row["comparison"] for row in result["comparisons"]} == {
        "not_observed_in_current", "new_in_current"}
    assert result["fixed_count"] is None


def test_scan_comparison_withholds_possible_move_for_ambiguous_or_unqualified_context():
    def traced(path, line, operation="WebView.loadUrl", qualified=True):
        item = finding(path, line)
        trace_sink = {"operation": operation, "line": line}
        if qualified:
            trace_sink["source_qualified_method_identity"] = "com.example.Route#route(android.content.Intent)"
        item["metadata"] = {"source_sink_trace": {"sink": trace_sink}}
        return item

    ambiguous = compare_scans(
        scan("before", [traced("src/A.java", 1), traced("src/B.java", 2)], "a" * 64),
        scan("after", [traced("src/C.java", 3)], "b" * 64))
    assert ambiguous["relocation_leads"] == []
    changed_operation = compare_scans(
        scan("before", [traced("src/A.java", 1)], "a" * 64),
        scan("after", [traced("src/C.java", 3, operation="Intent.startActivity")], "b" * 64))
    assert changed_operation["relocation_leads"] == []
    unqualified = compare_scans(
        scan("before", [traced("src/A.java", 1, qualified=False)], "a" * 64),
        scan("after", [traced("src/C.java", 3, qualified=False)], "b" * 64))
    assert unqualified["relocation_leads"] == []


def test_scan_comparison_does_not_treat_missing_artifact_hashes_as_equal():
    result = compare_scans(scan("before", [], None), scan("after", [], None))
    assert result["relation"]["artifact_changed"] is None
    assert result["relation"]["artifact_comparison_status"] == "unknown"
    malformed = compare_scans(scan("before", [], "not-a-digest"), scan("after", [], "also-not"))
    assert malformed["relation"]["artifact_changed"] is None
    assert malformed["relation"]["baseline_artifact_sha256"] is None



def test_comparison_exposes_recorded_execution_parity_without_claiming_equivalence():
    before = scan("before", [], "a" * 64)
    after = scan("after", [], "b" * 64)
    before.update(artifact_provenance={"tools": {"jadx": {"version": "1"}}},
                  coverage={"java": {"static_status": "completed"}})
    after.update(artifact_provenance={"tools": {"jadx": {"version": "1"}}},
                 coverage={"java": {"static_status": "not_started"}})
    parity = compare_scans(before, after)["execution_parity"]
    assert parity["tool_versions"] == "same_recorded_value"
    assert parity["coverage_records"] == "different_recorded_value"
    assert "not analyzer or coverage equivalence" in parity["interpretation"]
    missing = compare_scans(scan("x", [], None), scan("y", [], None))["execution_parity"]
    assert missing["tool_versions"] == missing["coverage_records"] == "unknown"
    empty = scan("e1", [], None); empty2 = scan("e2", [], None)
    empty.update(artifact_provenance={"tools": {}}, coverage={})
    empty2.update(artifact_provenance={"tools": {}}, coverage={})
    assert compare_scans(empty, empty2)["execution_parity"]["coverage_records"] == "unknown"
    large = scan("l1", [], None); large2 = scan("l2", [], None)
    large["coverage"] = large2["coverage"] = {"detail": "x" * 300_000}
    assert compare_scans(large, large2)["execution_parity"]["coverage_records"] == "unknown"

def test_read_only_comparison_endpoint_is_authenticated_and_does_not_mutate_scans():
    web = importlib.import_module("mobileag.web.app")
    repo = ScanRepository(web.OUTPUT_DIR)
    baseline = scan("compare_base_synthetic", [finding("src/A.java", 12)], "a" * 64)
    current = scan("compare_current_synthetic", [], "b" * 64)
    baseline["revision"] = current["revision"] = 0
    repo.save(baseline); repo.save(current)
    anon = TestClient(web.app)
    assert anon.get("/api/scans/compare_current_synthetic/comparison/compare_base_synthetic").status_code == 401
    client = TestClient(web.app, headers={"Authorization": "Bearer " + web.app.state.auth_token})
    response = client.get("/api/scans/compare_current_synthetic/comparison/compare_base_synthetic")
    assert response.status_code == 200
    body = response.json()
    assert body["relation"]["baseline_scan_id"] == "compare_base_synthetic"
    assert body["comparisons"][0]["interpretation"] == "not_proof_of_fix"
    assert repo.get("compare_base_synthetic")["revision"] == 0
    assert repo.get("compare_current_synthetic")["revision"] == 0
