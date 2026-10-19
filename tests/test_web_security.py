import importlib

from fastapi.testclient import TestClient


def test_api_landing_and_api_requires_bearer():
    web = importlib.import_module("mobileag.web.app")
    client = TestClient(web.app)

    assert client.get("/").status_code == 200
    assert client.get("/").json()["browser_ui"] == "disabled"
    assert client.get("/ui").status_code == 404
    assert client.get("/static/interface.css").status_code == 200
    assert client.get("/docs").status_code == 401
    assert client.get("/redoc").status_code == 401
    assert client.get("/api/status").status_code == 401


def test_root_reports_api_mode_and_static_legacy_assets_are_not_the_ui():
    web = importlib.import_module("mobileag.web.app")
    client = TestClient(web.app)
    token = web.app.state.auth_token
    headers = {"Authorization": f"Bearer {token}"}
    root = client.get("/", headers=headers)
    static = client.get("/static/interface.js", headers=headers)
    docs = client.get("/docs", headers=headers)
    redoc = client.get("/redoc", headers=headers)
    assert root.status_code == 200 and root.json()["browser_ui"] == "disabled"
    assert static.status_code == 200
    assert docs.status_code == 404
    assert redoc.status_code == 404
    assert "set-cookie" not in root.headers
