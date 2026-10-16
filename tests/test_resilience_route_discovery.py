"""Bounded source-root discovery for the resilience API route."""
import importlib

from fastapi.testclient import TestClient

web = importlib.import_module("mobileag.web.app")


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(web, "OUTPUT_DIR", tmp_path / "output")
    web.repository().save({"scan_id": "resilience_fixture", "status": "completed",
                           "package_name": "org.example.synthetic", "findings": []})
    return TestClient(web.app, headers={"Authorization": "Bearer " + web.app.state.auth_token})


def test_resilience_route_uses_bounded_compatibility_root(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    root = web.OUTPUT_DIR / "resilience_fixture" / "unusual" / "smali"
    root.mkdir(parents=True)
    (root / "Example.smali").write_text('.class Lx/Example;\n', encoding="utf-8")

    response = client.get("/api/scans/resilience_fixture/resilience")

    assert response.status_code == 200, response.text
    coverage = response.json()["coverage"]
    assert coverage["static_status"] == "analyzed_heuristically"
    assert coverage["root_discovery"] == {
        "status": "bounded_fallback", "roots_found": 1,
        "entries_examined": 3, "limits_reached": False,
    }


def test_resilience_route_includes_all_known_multidex_roots(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    base = web.OUTPUT_DIR / "resilience_fixture" / "apktool_out"
    primary = base / "smali"
    secondary = base / "smali_classes2"
    primary.mkdir(parents=True)
    secondary.mkdir()
    (primary / "Primary.smali").write_text('.class Lx/Primary;\n', encoding="utf-8")
    (secondary / "Secondary.smali").write_text(
        '.class Lx/Secondary;\nconst-string v0, "magisk"\n', encoding="utf-8")

    response = client.get("/api/scans/resilience_fixture/resilience")

    assert response.status_code == 200, response.text
    document = response.json()
    assert document["coverage"]["static_status"] == "analyzed_heuristically"
    assert document["coverage"]["source_files_analyzed"] == 2
    assert document["coverage"]["root_discovery"]["roots_found"] == 2
    assert document["coverage"]["root_discovery"]["status"] == "known_layout"
    assert "magisk" in document["vectors"]["root_detection"]["indicators"]


def test_resilience_route_does_not_choose_ambiguous_fallback_root(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    scan_dir = web.OUTPUT_DIR / "resilience_fixture"
    for name in ("first", "second"):
        root = scan_dir / name / "smali"
        root.mkdir(parents=True)
        (root / "Example.smali").write_text('.class Lx/Example;\n', encoding="utf-8")

    response = client.get("/api/scans/resilience_fixture/resilience")

    assert response.status_code == 200, response.text
    coverage = response.json()["coverage"]
    assert coverage["static_status"] == "not_analyzed"
    assert coverage["root_discovery"]["status"] == "not_analyzed_ambiguous_roots"
    assert coverage["root_discovery"]["roots_found"] == 2
    assert response.json()["overall_score"] is None


def test_resilience_route_does_not_follow_known_layout_symlink(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    scan_dir = web.OUTPUT_DIR / "resilience_fixture"
    external = tmp_path / "outside" / "smali"
    external.mkdir(parents=True)
    scan_dir.mkdir(parents=True, exist_ok=True)
    (external / "Example.smali").write_text(
        '.class Lx/Example;\nconst-string v0, "magisk"\n', encoding="utf-8")
    (scan_dir / "apktool_out").symlink_to(external.parent, target_is_directory=True)

    response = client.get("/api/scans/resilience_fixture/resilience")

    assert response.status_code == 200, response.text
    coverage = response.json()["coverage"]
    assert coverage["static_status"] == "not_analyzed"
    assert "root_discovery" in coverage
    assert "magisk" not in str(response.json()["vectors"])
