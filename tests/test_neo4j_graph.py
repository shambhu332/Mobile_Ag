import pytest

from mobileag.knowledge.neo4j_graph import AttackGraph
from mobileag.knowledge.schemas import APIEndpointNode, ComponentNode
from mobileag.reporting.finding import Finding


class _Session:
    def __init__(self, calls):
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def run(self, query, **params):
        self.calls.append((query, params))
        return None


class _Driver:
    def __init__(self):
        self.calls = []

    def session(self):
        return _Session(self.calls)


class _ExportResult:
    def __init__(self, record):
        self.record = record

    def __aiter__(self):
        async def records():
            yield self.record
        return records()


class _ExportSession(_Session):
    async def run(self, query, **params):
        return _ExportResult({
            "a": {"scan_id": "scan-a", "package_name": "sample", "version": "1"},
            "rel_type": "HAS_VULNERABILITY",
            "target": {"finding_id": '["scan-a","finding","finding-1"]',
                       "display_finding_id": "finding-1", "title": "Review candidate"},
            "target_labels": ["Vulnerability"],
        })


class _ExportDriver:
    def session(self):
        return _ExportSession([])


@pytest.mark.asyncio
async def test_graph_entities_are_scan_scoped_and_keep_display_values():
    graph = AttackGraph.__new__(AttackGraph)
    graph._connected = True
    graph.driver = _Driver()
    component = ComponentNode(name="com.example.MainActivity", component_type="activity", exported=True)
    finding = Finding(id="candidate-1", title="Review candidate", description="Synthetic test")
    endpoint = APIEndpointNode(url="https://api.example.invalid/v1/profile", method="GET")

    for scan_id in ("scan-a", "scan-b"):
        await graph.add_component(scan_id, component)
        await graph.add_finding(scan_id, finding)
        await graph.add_api_endpoint(scan_id, endpoint)

    component_params = [p for q, p in graph.driver.calls if "MERGE (c:Component" in q]
    finding_params = [p for q, p in graph.driver.calls if "MERGE (v:Vulnerability" in q]
    endpoint_params = [p for q, p in graph.driver.calls if "MERGE (e:APIEndpoint" in q]
    assert len(component_params) == len(finding_params) == len(endpoint_params) == 2
    for rows, display_key, display_value in (
        (component_params, "display_name", component.name),
        (finding_params, "display_finding_id", finding.id),
        (endpoint_params, "display_url", endpoint.url),
    ):
        assert rows[0]["node_key"] != rows[1]["node_key"]
        assert [row[display_key] for row in rows] == [display_value, display_value]

    # Finding serialization must use the actual Finding model field, not a missing legacy alias.
    assert finding_params[0]["cwe"] == finding.cwe_id
    assert finding_params[0]["scan_id"] == "scan-a"


def test_scoped_keys_are_stable_and_type_distinct():
    from mobileag.knowledge.neo4j_graph import _scoped_key

    assert _scoped_key("scan", "component", "same") == _scoped_key("scan", "component", "same")
    assert _scoped_key("scan-a", "component", "same") != _scoped_key("scan-b", "component", "same")
    assert _scoped_key("scan", "component", "same") != _scoped_key("scan", "api", "same")


@pytest.mark.asyncio
async def test_visjs_vulnerability_node_carries_original_finding_id():
    graph = AttackGraph.__new__(AttackGraph)
    graph._connected = True
    graph.driver = _ExportDriver()

    result = await graph.export_visjs_graph("scan-a")

    finding_nodes = [node for node in result["nodes"] if node["group"] == "vulnerability"]
    assert len(finding_nodes) == 1
    assert finding_nodes[0]["id"] == '["scan-a","finding","finding-1"]'
    assert finding_nodes[0]["finding_id"] == "finding-1"
