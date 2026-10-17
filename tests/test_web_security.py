import importlib

from fastapi.testclient import TestClient


def test_dashboard_bootstraps_httponly_local_browser_session_without_token_prompt():
    web = importlib.import_module("mobileag.web.app")
    client = TestClient(web.app)

    page = client.get("/")
    cookie = page.headers.get("set-cookie", "")
    assert page.status_code == 200
    assert "mobileag_session=" in cookie
    assert "httponly" in cookie.lower()
    assert "samesite=strict" in cookie.lower()
    assert "Session access token" not in page.text
    assert "#session-token" not in page.text
    assert client.get("/api/status").status_code == 200


def test_local_browser_session_cookie_is_not_issued_for_foreign_origin():
    web = importlib.import_module("mobileag.web.app")
    response = TestClient(web.app).get("/", headers={"Origin": "https://attacker.invalid"})
    assert response.status_code == 403
    assert "set-cookie" not in response.headers


def test_websocket_accepts_browser_cookie_without_token_message():
    web = importlib.import_module("mobileag.web.app")
    client = TestClient(web.app)
    client.get("/")
    with client.websocket_connect("/ws/telemetry") as websocket:
        assert websocket.receive_json()["type"] == "connection_established"
