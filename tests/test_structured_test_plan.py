"""Synthetic-only API and persistence checks for manual test-plan records."""
import importlib
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

web = importlib.import_module("mobileag.web.app")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "OUTPUT_DIR", tmp_path / "output")
    return TestClient(web.app, headers={"Authorization": "Bearer " + web.app.state.auth_token})


def scan(scan_id, *, package="org.example.synthetic", digest="a" * 64, status="completed"):
    return {"scan_id": scan_id, "status": status, "package_name": package,
            "artifact_sha256": digest, "version": "1.0-synthetic", "revision": 0,
            "findings": [{"id": "finding-1", "cwe_id": "CWE-829"}]}


def request_body(**overrides):
    body = {
        "roles": [{"id": "viewer", "purpose": "Synthetic least-privileged role"}],
        "flows": [{"id": "share", "name": "Open shared item",
                   "entrypoint": "Document share intent", "sensitive_operation": "Read item"}],
        "test_account_aliases": [{"alias": "researcher_a", "role_id": "viewer"}],
        "coverage": [{"surface": "manifest_ipc", "state": "not_tested",
                      "gap_reason": "No device authorized"}],
        "evidence": [{"id": "note-1", "flow_id": "share", "finding_id": "finding-1",
                      "outcome": "observed", "summary": "Synthetic observation; no exploit claim",
                      "steps": ["Run the synthetic fixture"]}],
    }
    body.update(overrides)
    return body


def test_plan_api_persists_scan_bound_manual_workflow_with_revision_and_redaction(client):
    repo = web.repository()
    repo.save(scan("plan_current"))
    repo.save(scan("plan_baseline", digest="b" * 64))
    assert TestClient(web.app).get("/api/scans/plan_current/test-plan").status_code == 401
    body = request_body(retest_of_scan_id="plan_baseline")
    body["evidence"][0]["summary"] = "Synthetic note password=UNIQUE-FAKE-SECRET-DO-NOT-KEEP"
    created = client.put("/api/scans/plan_current/test-plan", json=body)
    assert created.status_code == 200, created.text
    plan = created.json()
    assert plan["schema_version"] == 1 and plan["plan_revision"] == 0
    assert plan["scope"] == {"package_name": "org.example.synthetic", "artifact_sha256": "a" * 64,
                             "app_version": "1.0-synthetic"}
    assert plan["evidence_interpretation"] == "manual_notes_unverified_not_execution_or_independent_proof"
    assert plan["retest_baseline_binding"] == {
        "scan_id": "plan_baseline", "package_name": "org.example.synthetic",
        "artifact_sha256": "b" * 64, "app_version": "1.0-synthetic",
    }
    assert "UNIQUE-FAKE-SECRET-DO-NOT-KEEP" not in str(repo.get_test_plan("plan_current"))
    assert "[REDACTED]" in repo.get_test_plan("plan_current")["evidence"][0]["summary"]
    assert client.get("/api/scans/plan_current/test-plan").json() == repo.get_test_plan("plan_current")

    stale = client.put("/api/scans/plan_current/test-plan", json=request_body(expected_revision=4))
    assert stale.status_code == 409
    updated = client.put("/api/scans/plan_current/test-plan",
                         json=request_body(expected_revision=0, roles=[{"id": "viewer", "purpose": "Updated"}]))
    assert updated.status_code == 200 and updated.json()["plan_revision"] == 1


@pytest.mark.parametrize("body,expected_status", [
    ({"roles": [], "password": "should-never-persist"}, 422),
    ({"test_account_aliases": [{"alias": "user", "role_id": "viewer", "password": "secret"}]}, 422),
    ({"coverage": [{"surface": "device_shell", "state": "attested"}]}, 422),
    ({"roles": [{"id": "viewer"}], "test_account_aliases": [{"alias": "a", "role_id": "unknown"}]}, 409),
    ({"flows": [{"id": "share", "name": "Flow"}],
      "evidence": [{"id": "note", "flow_id": "outside"}]}, 409),
    ({"coverage": [{"surface": "manifest_ipc", "evidence_ref": "missing"}]}, 409),
])
def test_plan_schema_rejects_secrets_scope_expansion_and_bad_references(client, body, expected_status):
    web.repository().save(scan("plan_reject"))
    response = client.put("/api/scans/plan_reject/test-plan", json=body)
    assert response.status_code == expected_status
    assert web.repository().get_test_plan("plan_reject") is None


def test_plan_requires_completed_scan_and_valid_same_package_retest_baseline(client):
    repo = web.repository()
    repo.save(scan("plan_running", status="running"))
    assert client.put("/api/scans/plan_running/test-plan", json=request_body()).status_code == 409
    repo.save(scan("plan_done"))
    assert client.put("/api/scans/plan_done/test-plan",
                      json=request_body(retest_of_scan_id="missing_baseline")).status_code == 409
    repo.save(scan("plan_other_app", package="org.other.synthetic"))
    assert client.put("/api/scans/plan_done/test-plan",
                      json=request_body(retest_of_scan_id="plan_other_app")).status_code == 409


def test_plan_baseline_must_have_hash_and_planned_comparison_rechecks_frozen_binding(client):
    repo = web.repository()
    repo.save(scan("plan_current"))
    repo.save({"scan_id": "plan_baseline_no_hash", "status": "completed",
              "package_name": "org.example.synthetic", "findings": []})
    assert client.put("/api/scans/plan_current/test-plan",
                      json=request_body(retest_of_scan_id="plan_baseline_no_hash")).status_code == 409
    repo.save(scan("plan_baseline", digest="b" * 64))
    created = client.put("/api/scans/plan_current/test-plan",
                         json=request_body(retest_of_scan_id="plan_baseline"))
    assert created.status_code == 200
    compared = client.get("/api/scans/plan_current/planned-comparison")
    assert compared.status_code == 200, compared.text
    assert compared.json()["plan_binding"] == {
        "plan_revision": 0, "baseline_scan_id": "plan_baseline",
        "baseline_artifact_sha256": "b" * 64, "status": "artifact_binding_matches",
    }

    # Test the fail-closed condition that protects a stored retest relation.
    repo.save(scan("plan_baseline", digest="c" * 64))
    assert client.get("/api/scans/plan_current/planned-comparison").status_code == 409
    repo.save(scan("plan_baseline", digest="b" * 64) | {"version": "changed-version"})
    assert client.get("/api/scans/plan_current/planned-comparison").status_code == 409


def test_browser_plan_editor_assets_are_not_shipped():
    web_root=Path(__file__).resolve().parents[1] / "mobileag/web"
    assert not (web_root / "static").exists()
    assert not (web_root / "templates").exists()


def test_test_plan_migration_and_retention_are_local_and_scan_bound(client):
    repo = web.repository()
    repo.save(scan("plan_purge"))
    assert client.put("/api/scans/plan_purge/test-plan", json=request_body()).status_code == 200
    preview = client.get("/api/scans/plan_purge/retention").json()
    assert "manual test-plan records" in preview["deletes"]
    result = client.post("/api/scans/plan_purge/purge",
                         json={"confirmation": "plan_purge", "revision": 0})
    assert result.status_code == 200
    assert repo.get_test_plan("plan_purge") is None


def test_existing_sqlite_scan_database_gets_test_plan_table_migration(tmp_path):
    path = tmp_path / ".mobileag.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript("""CREATE TABLE scans(id TEXT PRIMARY KEY, created TEXT NOT NULL,
          status TEXT NOT NULL, revision INTEGER NOT NULL, document TEXT NOT NULL);
          CREATE TABLE decisions(id INTEGER PRIMARY KEY, scan_id TEXT, finding_id TEXT,
          at TEXT, verdict TEXT, notes TEXT, revision INTEGER, actor TEXT);""")
    from mobileag.web.repository import ScanRepository
    repo = ScanRepository(tmp_path)
    with repo.connection() as db:
        assert "test_plans" in {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "evidence" in {row[1] for row in db.execute("PRAGMA table_info(decisions)")}
