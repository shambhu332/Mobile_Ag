import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from mobileag.dast.device_metrics import DeviceMetricsCollector
from mobileag.dast.logcat_stream import LogcatStreamer
from mobileag.dast.shell_session import _validate_command
from mobileag.web import console_routes
from mobileag.web.console_routes import _scope_ok


def test_shell_console_accepts_only_single_read_only_commands():
    for command in ("id", "ps -A", "getprop ro.build.version.sdk", "dumpsys battery",
                    "pm list packages -3", "settings list secure"):
        _validate_command(command)
    for command in ("id; rm -rf /", "$(id)", "su -c id", "cat /data/data/app/token",
                    "settings put secure x y", "logcat -d", "ps -A | cat"):
        with pytest.raises(ValueError):
            _validate_command(command)


@pytest.mark.asyncio
async def test_metrics_require_guard_and_reject_package_shell_injection(monkeypatch):
    collector = DeviceMetricsCollector(adb_path="/not/used")
    calls = []
    async def spawn(*args, **kwargs):
        calls.append(args)
        raise AssertionError("invalid request must not launch ADB")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(PermissionError):
        await collector.collect_snapshot("device-1")
    with pytest.raises(ValueError):
        await collector.collect_snapshot("device-1", "com.example;id", guard=lambda: True)
    assert calls == []


def test_console_scope_requires_exact_device_action_and_package(monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-1")
    policy = {"devices": ["emulator-1"], "packages": ["org.example.app"],
              "origins": [], "methods": ["GET"], "actions": ["execute_adb", "logcat", "storage"]}
    state = SimpleNamespace(session_deadline=float("inf"), auth_token="token",
                            scope_repository=lambda: SimpleNamespace(get_policy=lambda: policy))
    assert _scope_ok(state, "token", "emulator-1")
    assert not _scope_ok(state, "wrong", "emulator-1")
    assert not _scope_ok(state, "token", "other-device")
    assert _scope_ok(state, "token", "emulator-1", "logcat", "org.example.app")
    assert not _scope_ok(state, "token", "emulator-1", "logcat", "org.other.app")
    assert not _scope_ok(state, "token", "emulator-1", "storage")


def _request(policy, monkeypatch):
    monkeypatch.setenv("MOBILEAG_ALLOWED_DEVICES", "emulator-1")
    state = SimpleNamespace(session_deadline=float("inf"), auth_token="token",
                            scope_repository=lambda: SimpleNamespace(get_policy=lambda: policy))
    return SimpleNamespace(state=SimpleNamespace(authenticated_token="token"), app=SimpleNamespace(state=state))


@pytest.mark.asyncio
async def test_metrics_route_passes_package_keyword_and_current_guard(monkeypatch):
    policy = {"devices": ["emulator-1"], "packages": [], "origins": [], "methods": ["GET"],
              "actions": ["execute_adb"]}
    collector = SimpleNamespace(collect_snapshot=AsyncMock(return_value={"serial": "emulator-1"}))
    monkeypatch.setattr(console_routes, "_metrics_collector", collector)
    result = await console_routes.get_device_metrics(_request(policy, monkeypatch), "emulator-1", None)
    assert result["serial"] == "emulator-1"
    collector.collect_snapshot.assert_awaited_once()
    assert collector.collect_snapshot.await_args.kwargs["guard"]()


@pytest.mark.asyncio
async def test_storage_route_requires_package_scope_and_passes_manager_guard(monkeypatch):
    policy = {"devices": ["emulator-1"], "packages": ["org.example.app"], "origins": [],
              "methods": ["GET"], "actions": ["storage"]}
    manager = SimpleNamespace(list_directory=AsyncMock(return_value={"entries": []}))
    monkeypatch.setattr(console_routes, "_file_manager", manager)
    result = await console_routes.list_files(
        _request(policy, monkeypatch), "emulator-1", "org.example.app", None)
    assert result["entries"] == []
    assert manager.list_directory.await_args.args == ("emulator-1", "/sdcard/Android/data/org.example.app")
    assert manager.list_directory.await_args.kwargs["guard"]()


@pytest.mark.asyncio
async def test_live_logcat_uses_target_pids_and_redacts_before_yield(monkeypatch):
    class FakeProcess:
        def __init__(self, *, lines=None, stdout=None):
            self.stdout = stdout or asyncio.StreamReader()
            self.returncode = 0
            for line in lines or []:
                self.stdout.feed_data(line.encode() + b"\n")
            self.stdout.feed_eof()
        async def communicate(self): return b"123 456", b""
        async def wait(self): return 0
        def kill(self): self.returncode = -9

    records = [
        "10-18 12:00:00.000  999  999 I Other: org.example.app password=leak",
        "10-18 12:00:00.001  123  123 I App: password=syntheticSecretValue",
        "10-18 12:00:00.002  700  700 I ActivityManager: Start proc 700:org.example.app:worker/u0a10 for service",
        "10-18 12:00:00.003  700  700 E App: Bearer eyJabcdefghijk.abcdefghijk.abcdefghijk",
    ]
    calls = 0
    async def spawn(*args, **kwargs):
        nonlocal calls
        calls += 1
        return FakeProcess(lines=records) if calls == 1 else FakeProcess()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    streamer = LogcatStreamer(adb_path="adb")
    output = [row async for row in streamer.stream(
        "emulator-1", package_filter="org.example.app", max_duration=5, guard=lambda: True)]
    assert [row["pid"] for row in output] == [123, 700, 700]
    assert "syntheticSecretValue" not in output[0]["message"]
    assert "[REDACTED]" in output[2]["message"]
