import importlib

from fastapi.testclient import TestClient


def test_web_ui_routes_are_removed_and_api_requires_bearer():
    web = importlib.import_module("mobileag.web.app")
    client = TestClient(web.app)

    assert client.get("/").status_code == 401
    assert client.get("/static/interface.js").status_code == 401
    assert client.get("/docs").status_code == 401
    assert client.get("/redoc").status_code == 401
    assert client.get("/api/status").status_code == 401


def test_authenticated_root_and_static_routes_do_not_serve_ui():
    web = importlib.import_module("mobileag.web.app")
    client = TestClient(web.app)
    token = web.app.state.auth_token
    headers = {"Authorization": f"Bearer {token}"}
    root = client.get("/", headers=headers)
    static = client.get("/static/interface.js", headers=headers)
    docs = client.get("/docs", headers=headers)
    redoc = client.get("/redoc", headers=headers)
    assert root.status_code == 404 and "text/html" not in root.headers.get("content-type", "")
    assert static.status_code == 404
    assert docs.status_code == 404
    assert redoc.status_code == 404
    assert "set-cookie" not in root.headers
