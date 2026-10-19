"""Tests for Diff Engine (/api/diff) and Executive Reporting (/api/scans/{scan_id}/report.*)."""

import importlib
import pytest
from fastapi.testclient import TestClient

web = importlib.import_module("mobileag.web.app")


@pytest.fixture
def client():
    return TestClient(web.app, headers={"Authorization": "Bearer " + web.app.state.auth_token})


@pytest.fixture
def unauth_client():
    return TestClient(web.app)


def test_diff_endpoint_requires_auth(unauth_client):
    res = unauth_client.post("/api/diff", json={"baseline": "v1", "target": "v2"})
    assert res.status_code == 401


def test_diff_endpoint_validation(client):
    res = client.post("/api/diff", json={})
    assert res.status_code == 400


def test_diff_endpoint_synthetic_demo(client):
    res = client.post("/api/diff", json={"baseline": "scan_v2.4.0_baseline", "target": "scan_v2.4.1_current"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "scorecard" in data
    assert data["scorecard"]["introduced_flaws"] > 0
    assert data["scorecard"]["resolved_flaws"] > 0
    assert len(data["comparisons"]) > 0
    assert len(data["component_changes"]) > 0
    assert len(data["permission_changes"]) > 0
    assert len(data["security_notes"]) > 0


def test_diff_endpoint_real_scans(client):
    repo = web.repository()
    scan_base = {
        "scan_id": "test_diff_base",
        "status": "completed",
        "package_name": "org.example.diffapp",
        "artifact_sha256": "1" * 64,
        "findings": [
            {
                "id": "f1",
                "detection_method": "TaintEngine",
                "cwe_id": "CWE-89",
                "file_path": "src/A.java",
                "line_number": 10,
                "status": "CONFIRMED",
            },
            {
                "id": "f2",
                "detection_method": "TaintEngine",
                "cwe_id": "CWE-798",
                "file_path": "src/B.java",
                "line_number": 20,
                "status": "UNVERIFIED",
            },
        ],
        "components": [{"name": "org.example.diffapp.OldActivity", "exported": False}],
        "manifest_data": {"permissions": ["android.permission.INTERNET"]},
    }
    scan_curr = {
        "scan_id": "test_diff_curr",
        "status": "completed",
        "package_name": "org.example.diffapp",
        "artifact_sha256": "2" * 64,
        "findings": [
            {
                "id": "f1",
                "detection_method": "TaintEngine",
                "cwe_id": "CWE-89",
                "file_path": "src/A.java",
                "line_number": 10,
                "status": "CONFIRMED",
            },
            {
                "id": "f3",
                "detection_method": "TaintEngine",
                "cwe_id": "CWE-287",
                "file_path": "src/C.java",
                "line_number": 30,
                "status": "UNVERIFIED",
            },
        ],
        "components": [
            {"name": "org.example.diffapp.NewActivity", "exported": True},
        ],
        "manifest_data": {"permissions": ["android.permission.INTERNET", "android.permission.CAMERA"]},
    }
    repo.save(scan_base)
    repo.save(scan_curr)

    res = client.post("/api/diff", json={"baseline": "test_diff_base", "target": "test_diff_curr"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["mode"] == "scan_comparison"
    assert data["scorecard"]["introduced_flaws"] == 1
    assert data["scorecard"]["resolved_flaws"] == 1
    comps = {c["file"]: c["comparison"] for c in data["comparisons"]}
    assert comps["src/A.java"] == "observed_in_both"
    assert comps["src/B.java"] == "not_observed_in_current"
    assert comps["src/C.java"] == "new_in_current"


def test_reports_demo_endpoints(client):
    # HTML report
    res_html = client.get("/api/scans/demo/report.html")
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert "MobileAg Security Assessment Report" in res_html.text
    assert "com.vulnerable.bank" in res_html.text

    # Markdown report
    res_md = client.get("/api/scans/demo/report.md")
    assert res_md.status_code == 200
    assert "text/markdown" in res_md.headers["content-type"]
    assert "Executive Summary" in res_md.text

    # JSON report
    res_json = client.get("/api/scans/demo/report.json")
    assert res_json.status_code == 200
    assert res_json.json()["scan_id"] == "demo"
    assert len(res_json.json()["findings"]) > 0

    # SARIF demo export
    res_sarif = client.get("/api/scans/demo/sarif")
    assert res_sarif.status_code == 200
    assert res_sarif.json()["version"] == "2.1.0"

    # CycloneDX demo export
    res_cdx = client.get("/api/scans/demo/cyclonedx.xml")
    assert res_cdx.status_code == 200
    assert "application/xml" in res_cdx.headers["content-type"]
    assert "<bom" in res_cdx.text

    # SPDX demo export
    res_spdx = client.get("/api/scans/demo/spdx")
    assert res_spdx.status_code == 200
    assert res_spdx.json()["spdxVersion"] == "SPDX-2.3"
