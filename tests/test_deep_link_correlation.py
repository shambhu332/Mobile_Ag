from mobileag.analysis.deep_link_correlation import correlate_manifest_deep_link_flows
from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer


JAVA_ROUTE_FLOW = '''package com.example;
import android.content.Intent;
import android.net.Uri;
import android.webkit.WebView;
class Route {
  void onCreate(Intent intent, WebView web) {
    Uri incoming = intent.getData();
    String next = incoming.getQueryParameter("next");
    web.loadUrl(next);
  }
}'''


def _flow_candidate():
    findings = JavaAstTaintAnalyzer().analyze(JAVA_ROUTE_FLOW, "com/example/Route.java")
    assert findings is not None
    candidate = next(item for item in findings
                     if item.metadata.get("source_kind") == "URI_QUERY_PARAM")
    return candidate


def _manifest(exported=True, package="com.example"):
    component = {"name": ".Route", "type": "activity", "exported": exported,
                 "intent_filters": [{"actions": ["android.intent.action.VIEW"]}]}
    return {
        "package_name": package,
        "components": [component],
        "deep_links": [{"component": ".Route", "filter_index": 0,
                        "scheme": "fixture", "host": "route.invalid",
                        "path": "/open", "path_kind": "path", "uri": "fixture://route.invalid/open",
                        "exported": exported}],
    }


def test_uri_taint_flow_correlates_to_same_qualified_exported_route_class_only():
    candidate = _flow_candidate()

    result = correlate_manifest_deep_link_flows([candidate], _manifest())

    assert result["status"] == "bounded_same_class_join_completed"
    assert result["uri_flow_candidates"] == 1
    assert result["correlated_flows"] == 1
    assert result["unmatchable_flows"] == 0
    correlation = candidate.metadata["manifest_route_correlation"]
    assert correlation["status"] == "same_ast_owner_as_exported_manifest_uri_route"
    assert correlation["component_class"] == "com.example.Route"
    assert correlation["entrypoint_reachability"] == "not_established"
    assert correlation["runtime_verified"] is False
    assert correlation["proof_status"] == "not_proven"


def test_private_or_different_package_route_is_not_correlated():
    private_candidate = _flow_candidate()
    private_result = correlate_manifest_deep_link_flows([private_candidate], _manifest(exported=False))
    assert private_result["correlated_flows"] == 0
    assert "manifest_route_correlation" not in private_candidate.metadata

    other_package_candidate = _flow_candidate()
    other_result = correlate_manifest_deep_link_flows(
        [other_package_candidate], _manifest(package="org.other"))
    assert other_result["correlated_flows"] == 0
    assert other_result["unmatchable_flows"] == 1
    assert "manifest_route_correlation" not in other_package_candidate.metadata


def test_alias_route_can_correlate_to_target_owner_without_upgrading_proof():
    candidate = _flow_candidate()
    manifest = _manifest()
    manifest["components"] = [
        {"name": ".RouteAlias", "alias_target": ".Route", "type": "activity-alias",
         "exported": True, "intent_filters": [{}]},
    ]
    manifest["deep_links"][0]["component"] = ".RouteAlias"

    result = correlate_manifest_deep_link_flows([candidate], manifest)

    assert result["correlated_flows"] == 1
    assert candidate.metadata["manifest_route_correlation"]["component_class"] == "com.example.Route"
    assert candidate.metadata["manifest_route_correlation"]["proof_status"] == "not_proven"


def test_manifest_route_context_is_bounded_before_finding_persistence():
    candidate = _flow_candidate()
    manifest = _manifest()
    manifest["deep_links"][0]["uri"] = "fixture://route.invalid/" + ("x" * 100_000)

    correlate_manifest_deep_link_flows([candidate], manifest)

    route = candidate.metadata["manifest_route_correlation"]["routes"][0]
    assert len(route["uri"]) == 256
    assert route["host"] == "route.invalid"


def test_correlation_reports_partial_when_route_inventory_is_truncated():
    candidate = _flow_candidate()
    manifest = _manifest()
    manifest["deep_links"] *= 5001

    result = correlate_manifest_deep_link_flows([candidate], manifest)

    assert result["status"] == "partial"
    assert result["inventory_truncated"] is True
    assert result["routes_seen"] == result["inventory_limits"]["routes"] == 5000
    assert result["routes_omitted_by_limit"] == 1
    assert result["proof_status"] == "not_proven"


def test_finding_inventory_cap_is_reported_without_claiming_full_correlation():
    result = correlate_manifest_deep_link_flows([object()] * 10001, _manifest())

    assert result["status"] == "partial"
    assert result["findings_seen"] == result["inventory_limits"]["findings"] == 10000
    assert result["findings_omitted_by_limit"] == 1
    assert result["inventory_truncated"] is True


def test_component_inventory_cap_downgrades_route_join_to_partial():
    manifest = _manifest()
    manifest["components"] = [{"name": f".Component{index}", "type": "activity"}
                               for index in range(5001)]

    result = correlate_manifest_deep_link_flows([_flow_candidate()], manifest)

    assert result["status"] == "partial"
    assert result["components_seen"] == result["inventory_limits"]["components"] == 5000
    assert result["components_omitted_by_limit"] == 1
    assert result["inventory_truncated"] is True
