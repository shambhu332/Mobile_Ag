"""Tests for Port Forwarding & Reverse Tunnels and Intent & ContentProvider Crafting APIs."""

import importlib
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

web = importlib.import_module("mobileag.web.app")


@pytest.fixture
def client():
    return TestClient(web.app, headers={"Authorization": "Bearer " + web.app.state.auth_token})


@pytest.fixture
def unauth_client():
    return TestClient(web.app)


def test_forward_endpoint_requires_auth(unauth_client):
    res = unauth_client.get("/api/dast/forward?serial=emulator-5554")
    assert res.status_code == 401

    res = unauth_client.post("/api/dast/forward", json={"serial": "emulator-5554", "local": "tcp:8080", "remote": "tcp:8080"})
    assert res.status_code == 401

    res = unauth_client.request("DELETE", "/api/dast/forward", json={"serial": "emulator-5554", "local": "tcp:8080"})
    assert res.status_code == 401


def test_intent_endpoint_requires_auth(unauth_client):
    res = unauth_client.post("/api/dast/intent/send", json={"serial": "emulator-5554", "target_type": "activity"})
    assert res.status_code == 401


def test_forward_endpoint_device_scope_enforcement(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "allowed-device-1")
    res = client.get("/api/dast/forward?serial=rogue-device")
    assert res.status_code == 403
    assert "scope" in res.json()["detail"].lower()


def test_list_port_forwards_success(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")

    mock_exec = AsyncMock()
    # First call: forward --list -> returns lines
    # Second call: reverse --list -> returns lines
    mock_exec.side_effect = [
        (0, b"emulator-5554 tcp:8080 tcp:8080\nemulator-5554 tcp:8081 localabstract:sock1\n", b""),
        (0, b"emulator-5554 tcp:27042 tcp:27042\n", b""),
    ]

    with patch.object(web.adb_manager, "_exec_cmd", mock_exec):
        res = client.get("/api/dast/forward?serial=emulator-5554")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["serial"] == "emulator-5554"
        forwards = data["forwards"]
        assert len(forwards) == 3

        f1 = forwards[0]
        assert f1["type"] == "forward"
        assert f1["local"] == "tcp:8080"
        assert f1["remote"] == "tcp:8080"

        rev = [f for f in forwards if f["type"] == "reverse"][0]
        assert rev["local"] == "tcp:27042"
        assert rev["remote"] == "tcp:27042"


def test_create_port_forward_forward_and_reverse(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")

    mock_exec = AsyncMock()
    mock_exec.return_value = (0, b"", b"")

    with patch.object(web.adb_manager, "_exec_cmd", mock_exec):
        # Create normal forward
        res = client.post("/api/dast/forward", json={
            "serial": "emulator-5554",
            "local": "tcp:8080",
            "remote": "tcp:8080",
            "reverse": False,
        })
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["type"] == "forward"

        # Verify command arguments passed
        mock_exec.assert_called_with(["-s", "emulator-5554", "forward", "tcp:8080", "tcp:8080"], timeout=5.0)

        # Create reverse tunnel
        res = client.post("/api/dast/forward", json={
            "serial": "emulator-5554",
            "local": "tcp:27042",
            "remote": "tcp:27042",
            "reverse": True,
        })
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["type"] == "reverse"
        mock_exec.assert_called_with(["-s", "emulator-5554", "reverse", "tcp:27042", "tcp:27042"], timeout=5.0)


def test_remove_port_forward_single_and_all(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")

    mock_exec = AsyncMock()
    mock_exec.return_value = (0, b"", b"")

    with patch.object(web.adb_manager, "_exec_cmd", mock_exec):
        # Remove single forward
        res = client.request("DELETE", "/api/dast/forward", json={
            "serial": "emulator-5554",
            "local": "tcp:8080",
            "reverse": False,
            "all": False,
        })
        assert res.status_code == 200
        mock_exec.assert_called_with(["-s", "emulator-5554", "forward", "--remove", "tcp:8080"], timeout=5.0)

        # Remove all reverse tunnels
        res = client.request("DELETE", "/api/dast/forward", json={
            "serial": "emulator-5554",
            "reverse": True,
            "all": True,
        })
        assert res.status_code == 200
        mock_exec.assert_called_with(["-s", "emulator-5554", "reverse", "--remove-all"], timeout=5.0)


def test_dispatch_custom_intent_activity(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")

    mock_exec = AsyncMock()
    mock_exec.return_value = (0, b"Starting: Intent { cmp=com.example.app/.MainActivity }", b"")

    with patch.object(web.adb_manager, "_exec_cmd", mock_exec):
        res = client.post("/api/dast/intent/send", json={
            "serial": "emulator-5554",
            "target_type": "activity",
            "component": "com.example.app/.MainActivity",
            "action": "android.intent.action.VIEW",
            "data_uri": "https://example.com/deeplink",
            "mime_type": "text/html",
            "categories": ["android.intent.category.BROWSABLE"],
            "flags": ["0x10000000"],
            "extras": [
                {"type": "string", "key": "ref", "value": "partner"},
                {"type": "bool", "key": "debug", "value": "true"},
                {"type": "int", "key": "level", "value": "5"},
            ]
        })
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["code"] == 0
        assert data["crashed"] is False
        assert "MainActivity" in data["output"]

        # Check call args
        call_args = mock_exec.call_args[0][0]
        assert "am" in call_args
        assert "start" in call_args
        assert "-n" in call_args and "com.example.app/.MainActivity" in call_args
        assert "-a" in call_args and "android.intent.action.VIEW" in call_args
        assert "-d" in call_args and "https://example.com/deeplink" in call_args
        assert "-t" in call_args and "text/html" in call_args
        assert "-c" in call_args and "android.intent.category.BROWSABLE" in call_args
        assert "-f" in call_args and "0x10000000" in call_args
        assert "--es" in call_args and "ref" in call_args
        assert "--ez" in call_args and "debug" in call_args
        assert "--ei" in call_args and "level" in call_args


def test_dispatch_custom_intent_broadcast_and_crash_detection(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")

    mock_exec = AsyncMock()
    mock_exec.return_value = (1, b"Broadcasting: Intent\njava.lang.SecurityException: Permission Denial\nCRASH in process", b"")

    with patch.object(web.adb_manager, "_exec_cmd", mock_exec):
        res = client.post("/api/dast/intent/send", json={
            "serial": "emulator-5554",
            "target_type": "broadcast",
            "component": "com.vulnerable.bank/.auth.BiometricAuthReceiver",
            "action": "com.vulnerable.bank.AUTH_SUCCESS",
            "extras": [
                {"type": "bool", "key": "authenticated", "value": "true"},
            ]
        })
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "error"
        assert data["code"] == 1
        assert data["crashed"] is True
        assert "SecurityException" in data["output"]


def test_dispatch_custom_content_provider_query(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")

    mock_exec = AsyncMock()
    mock_exec.return_value = (0, b"Row: 0 _id=1, username=admin, password=hash, balance=100000", b"")

    with patch.object(web.adb_manager, "_exec_cmd", mock_exec):
        res = client.post("/api/dast/intent/send", json={
            "serial": "emulator-5554",
            "target_type": "content_query",
            "data_uri": "content://com.vulnerable.bank.provider/accounts",
            "projection": "* FROM accounts WHERE 1=1 UNION SELECT 1,username,password,balance FROM users; --",
            "where": "1=1",
        })
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["code"] == 0
        assert "Row: 0" in data["output"]

        call_args = mock_exec.call_args[0][0]
        assert "content" in call_args
        assert "query" in call_args
        assert "--uri" in call_args and "content://com.vulnerable.bank.provider/accounts" in call_args
        assert "--projection" in call_args
        assert "--where" in call_args


def test_dispatch_custom_intent_invalid_target_type(client, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-5554")

    res = client.post("/api/dast/intent/send", json={
        "serial": "emulator-5554",
        "target_type": "invalid_operation_foo",
    })
    assert res.status_code == 400
    assert "Unknown target type" in res.json()["detail"]
