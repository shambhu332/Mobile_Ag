"""Console-mode API routes for MobileAg: device shell, metrics, file manager, and logcat.

Provides live Loupe-style browser console features over REST and WebSocket.
All routes are prefixed with /api/console and require bearer authentication.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from mobileag.web.security import authorized, check_device
from mobileag.web.policy import check_action
from mobileag.security.privacy import redact

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/console", tags=["console"])

# ---------------------------------------------------------------------------
# Optional DAST module imports – guarded so the router loads even if the
# new modules are not yet present in the package.
# ---------------------------------------------------------------------------

try:
    from mobileag.dast.logcat_stream import LogcatStreamer
except ImportError:
    LogcatStreamer = None  # type: ignore[assignment,misc]

try:
    from mobileag.dast.device_metrics import DeviceMetricsCollector
except ImportError:
    DeviceMetricsCollector = None  # type: ignore[assignment,misc]

try:
    from mobileag.dast.shell_session import ShellSession
except ImportError:
    ShellSession = None  # type: ignore[assignment,misc]

try:
    from mobileag.dast.file_manager import DeviceFileManager
except ImportError:
    DeviceFileManager = None  # type: ignore[assignment,misc]

try:
    from mobileag.dast.adb_manager import ADBManager
except ImportError:
    from mobileag.dast import ADBManager  # type: ignore[no-redef]

# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------

_logcat_streamer = LogcatStreamer() if LogcatStreamer is not None else None
_metrics_collector = DeviceMetricsCollector() if DeviceMetricsCollector is not None else None
_shell_session = ShellSession() if ShellSession is not None else None
_file_manager = DeviceFileManager() if DeviceFileManager is not None else None
_adb = ADBManager()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BLOCKED_PREFIXES = ("rm -rf /", "mkfs", "dd if=")
_MAX_CMD_LEN = 1024
_MAX_PROCESSES = 500
_WS_AUTH_TIMEOUT = 5.0          # seconds to receive the first auth frame
_WS_METRICS_OP_TIMEOUT = 90.0   # asyncio.wait_for guard for collect_snapshot
_WS_LOGCAT_LINE_TIMEOUT = 90.0  # asyncio.wait_for guard per logcat line

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ShellCommand(BaseModel):
    command: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_session(request: Request, app_state) -> None:
    """Raise 401 if the session is expired or the bearer token is invalid."""
    token = request.state.authenticated_token
    if (
        time.monotonic() >= getattr(app_state, "session_deadline", float("inf"))
        or not authorized(token, app_state.auth_token)
    ):
        raise HTTPException(status_code=401, detail="Session expired or revoked")


def _require_device(serial: str) -> None:
    """Raise 400 if *serial* is not in the configured allowed-devices list."""
    if not check_device(serial):
        raise HTTPException(
            status_code=400, detail="Device is outside configured scope"
        )


def _scope_ok(app_state, token: str, serial: str, action: str = "execute_adb",
              package: Optional[str] = None) -> bool:
    """Recheck the session, exact device and persisted, server-narrowed action."""
    if (time.monotonic() >= getattr(app_state, "session_deadline", float("inf"))
            or not authorized(token, app_state.auth_token) or not check_device(serial)):
        return False
    policy = app_state.scope_repository().get_policy() or {}
    if package is not None:
        if not re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+", package):
            return False
        if package not in policy.get("packages", []):
            return False
    return check_action(policy, action, {"serial": serial, "package_name": package})


def _require_console_action(request: Request, serial: str, action: str = "execute_adb",
                            package: Optional[str] = None):
    _require_session(request, request.app.state)
    _require_device(serial)
    token = request.state.authenticated_token
    if not _scope_ok(request.app.state, token, serial, action, package):
        raise HTTPException(status_code=403, detail="Device action is outside the saved assessment scope")
    return lambda: _scope_ok(request.app.state, token, serial, action, package)


def _package_storage_path(path: str, package: str) -> bool:
    """Permit only the selected app's public Android shared-storage roots."""
    if not re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+", package):
        return False
    roots = (f"/sdcard/Android/data/{package}", f"/sdcard/Android/media/{package}")
    return isinstance(path, str) and any(path == root or path.startswith(root + "/") for root in roots)


async def _ws_authenticate(websocket: WebSocket, app_state) -> str:
    """Authenticate a WebSocket connection via the first JSON message.

    Expects ``{"token": "<bearer>"}``.  Returns the validated token string.
    Closes the socket with code 1008 and raises ``WebSocketDisconnect`` on
    failure so callers can simply ``await _ws_authenticate(...)`` and proceed.
    """
    try:
        auth = await asyncio.wait_for(
            websocket.receive_json(), timeout=_WS_AUTH_TIMEOUT
        )
        if (
            not isinstance(auth, dict)
            or time.monotonic() >= getattr(app_state, "session_deadline", float("inf"))
            or not authorized(auth.get("token"), app_state.auth_token)
        ):
            await websocket.close(code=1008)
            raise WebSocketDisconnect(code=1008)
        return auth["token"]
    except (asyncio.TimeoutError, Exception):
        try:
            await websocket.close(code=1008)
        except Exception:
            pass
        raise WebSocketDisconnect(code=1008)


# ---------------------------------------------------------------------------
# Route 1 – GET /api/console/devices/{serial}/metrics  (REST snapshot)
# ---------------------------------------------------------------------------


@router.get("/devices/{serial}/metrics")
async def get_device_metrics(
    request: Request,
    serial: str,
    package: Optional[str] = Query(default=None),
) -> dict:
    """Return a single metrics snapshot for *serial*."""
    guard = _require_console_action(request, serial, package=package)

    if _metrics_collector is None:
        raise HTTPException(
            status_code=503, detail="DeviceMetricsCollector module not available"
        )
    try:
        snapshot = await asyncio.wait_for(
            _metrics_collector.collect_snapshot(serial, package_name=package, guard=guard),
            timeout=_WS_METRICS_OP_TIMEOUT,
        )
        return snapshot
    except asyncio.TimeoutError:
        logger.warning("collect_snapshot timed out for serial=%s", serial)
        raise HTTPException(status_code=504, detail="Metrics collection timed out")
    except Exception as exc:  # noqa: BLE001
        logger.error("collect_snapshot failed for serial=%s: %s", serial, exc)
        raise HTTPException(status_code=500, detail="Failed to collect device metrics")


# ---------------------------------------------------------------------------
# Route 2 – WS /api/console/devices/{serial}/metrics/stream
# ---------------------------------------------------------------------------


@router.websocket("/devices/{serial}/metrics/stream")
async def ws_metrics_stream(
    websocket: WebSocket,
    serial: str,
    package: Optional[str] = Query(default=None),
    interval: float = Query(default=2.0, ge=1.0, le=30.0),
    max_samples: int = Query(default=60, ge=1, le=150),
) -> None:
    """Stream metric snapshots for *serial* over WebSocket."""
    if not check_device(serial):
        await websocket.close(code=1008)
        return

    await websocket.accept()

    try:
        token = await _ws_authenticate(websocket, websocket.app.state)
    except WebSocketDisconnect:
        return

    if _metrics_collector is None:
        await websocket.send_json({"error": "DeviceMetricsCollector module not available"})
        await websocket.close(code=1011)
        return

    if not _scope_ok(websocket.app.state, token, serial, package=package):
        await websocket.close(code=1008)
        return
    guard = lambda: _scope_ok(websocket.app.state, token, serial, package=package)
    samples_sent = 0
    try:
        while samples_sent < max_samples:
            # Re-validate session on each iteration
            if not guard():
                await websocket.close(code=1008)
                break

            try:
                snapshot = await asyncio.wait_for(
                    _metrics_collector.collect_snapshot(serial, package_name=package, guard=guard),
                    timeout=_WS_METRICS_OP_TIMEOUT,
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "metrics collect_snapshot timed out (serial=%s); proceeding", serial
                )
                await asyncio.sleep(interval)
                continue

            await websocket.send_json(snapshot)
            samples_sent += 1
            await asyncio.sleep(interval)
    except WebSocketDisconnect:
        logger.debug("Metrics stream client disconnected (serial=%s)", serial)
    except PermissionError:
        await websocket.close(code=1008)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Metrics stream error (serial=%s): %s", serial, exc)
    finally:
        logger.debug(
            "Metrics stream closed after %d samples (serial=%s)", samples_sent, serial
        )


# ---------------------------------------------------------------------------
# Route 3 – WS /api/console/devices/{serial}/logcat
# ---------------------------------------------------------------------------


@router.websocket("/devices/{serial}/logcat")
async def ws_logcat_stream(
    websocket: WebSocket,
    serial: str,
    package: str = Query(...),
    level: Optional[str] = Query(default=None, pattern="^[VDIWEF]$"),
    tag: Optional[str] = Query(default=None),
) -> None:
    """Stream logcat lines for *serial* over WebSocket as JSON objects."""
    if not check_device(serial):
        await websocket.close(code=1008)
        return

    await websocket.accept()

    try:
        token = await _ws_authenticate(websocket, websocket.app.state)
    except WebSocketDisconnect:
        return

    if _logcat_streamer is None:
        await websocket.send_json({"error": "LogcatStreamer module not available"})
        await websocket.close(code=1011)
        return

    if not _scope_ok(websocket.app.state, token, serial, "logcat", package):
        await websocket.close(code=1008)
        return
    guard = lambda: _scope_ok(websocket.app.state, token, serial, "logcat", package)
    generator = _logcat_streamer.stream(
        serial, package_filter=package, level_filter=level, tag_filter=tag,
        max_duration=300.0, guard=guard
    )
    try:
        async for line in generator:
            if not guard():
                await websocket.close(code=1008)
                break
            # line is expected to be a dict; coerce to dict if it is a string
            if isinstance(line, str):
                payload: dict = {"line": line}
            else:
                payload = dict(line)
            await websocket.send_json(redact(payload))
    except WebSocketDisconnect:
        logger.debug("Logcat stream client disconnected (serial=%s)", serial)
    except PermissionError:
        await websocket.close(code=1008)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Logcat stream error (serial=%s): %s", serial, exc)
    finally:
        # Best-effort cleanup of the async generator
        try:
            await generator.aclose()
        except Exception:
            pass
        logger.debug("Logcat stream closed (serial=%s)", serial)


# ---------------------------------------------------------------------------
# Route 4 – POST /api/console/devices/{serial}/shell  (one-shot command)
# ---------------------------------------------------------------------------


@router.post("/devices/{serial}/shell")
async def run_shell_command(
    request: Request,
    serial: str,
    body: ShellCommand,
) -> dict:
    """Execute a single read-mostly diagnostic shell command on *serial*."""
    guard = _require_console_action(request, serial)

    command = body.command
    if len(command) > _MAX_CMD_LEN:
        raise HTTPException(
            status_code=400, detail="Command exceeds maximum allowed length"
        )
    # ShellSession enforces an exact read-only command grammar; a deny-list is
    # not a security boundary for shell metacharacters or alternate commands.

    if _shell_session is None:
        raise HTTPException(
            status_code=503, detail="ShellSession module not available"
        )

    try:
        result = await asyncio.wait_for(
            _shell_session.run_one(serial, command, guard=guard),
            timeout=60.0,
        )
        return {
            "output": result.get("output", ""),
            "exit_code": result.get("exit_code", -1),
            "serial": serial,
        }
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Shell command timed out")
    except Exception as exc:  # noqa: BLE001
        logger.error("Shell command failed (serial=%s): %s", serial, exc)
        raise HTTPException(status_code=500, detail="Shell command execution failed")


# ---------------------------------------------------------------------------
# Route 5 – GET /api/console/devices/{serial}/files  (directory listing)
# ---------------------------------------------------------------------------


@router.get("/devices/{serial}/files")
async def list_files(
    request: Request,
    serial: str,
    package: str = Query(...),
    path: Optional[str] = Query(default=None),
) -> dict:
    """List a directory on *serial*."""
    guard = _require_console_action(request, serial, "storage", package)
    path = path or f"/sdcard/Android/data/{package}"
    if not _package_storage_path(path, package):
        raise HTTPException(status_code=403, detail="Path is outside this package's shared-storage directory")

    if _file_manager is None:
        raise HTTPException(
            status_code=503, detail="DeviceFileManager module not available"
        )

    try:
        listing = await asyncio.wait_for(
            _file_manager.list_directory(serial, path, guard=guard),
            timeout=30.0,
        )
        return listing
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Directory listing timed out")
    except Exception as exc:  # noqa: BLE001
        logger.error("list_directory failed (serial=%s): %s", serial, exc)
        raise HTTPException(status_code=500, detail="Failed to list directory")


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Route 6 – GET /api/console/devices/{serial}/packages
# ---------------------------------------------------------------------------


@router.get("/devices/{serial}/packages")
async def list_packages(
    request: Request,
    serial: str,
    include_system: bool = Query(default=False),
) -> dict:
    """List installed packages on *serial*."""
    guard = _require_console_action(request, serial)

    if _file_manager is None:
        raise HTTPException(
            status_code=503, detail="DeviceFileManager module not available"
        )

    try:
        packages = await asyncio.wait_for(
            _file_manager.list_packages(serial, guard=guard, include_system=include_system),
            timeout=30.0,
        )
        return {"packages": packages}
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Package listing timed out")
    except Exception as exc:  # noqa: BLE001
        logger.error("list_packages failed (serial=%s): %s", serial, exc)
        raise HTTPException(status_code=500, detail="Failed to list packages")


# ---------------------------------------------------------------------------
# Route 7 – GET /api/console/devices/{serial}/info
# ---------------------------------------------------------------------------


@router.get("/devices/{serial}/info")
async def get_device_info(
    request: Request,
    serial: str,
) -> dict:
    """Return device properties for *serial*."""
    guard = _require_console_action(request, serial)

    if _file_manager is None:
        raise HTTPException(
            status_code=503, detail="DeviceFileManager module not available"
        )

    try:
        info = await asyncio.wait_for(
            _file_manager.get_device_info(serial, guard=guard),
            timeout=30.0,
        )
        return info
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Device info query timed out")
    except Exception as exc:  # noqa: BLE001
        logger.error("get_device_info failed (serial=%s): %s", serial, exc)
        raise HTTPException(status_code=500, detail="Failed to retrieve device info")


# ---------------------------------------------------------------------------
# Route 9 – GET /api/console/devices/{serial}/processes
# ---------------------------------------------------------------------------


@router.get("/devices/{serial}/processes")
async def list_processes(
    request: Request,
    serial: str,
) -> dict:
    """List running processes on *serial* via ``adb shell ps -A``."""
    guard = _require_console_action(request, serial)

    try:
        code, stdout, _ = await _adb._exec_cmd(
            ["-s", serial, "shell", "ps", "-A"], timeout=20.0, output_limit=512 * 1024)
        if not guard():
            raise HTTPException(status_code=401, detail="Session or scope revoked")
        if code != 0:
            raise HTTPException(status_code=502, detail="Process inventory unavailable")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Process listing timed out")
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("ps failed (serial=%s): %s", serial, exc)
        raise HTTPException(status_code=500, detail="Failed to list processes")

    lines = stdout.decode(errors="replace").splitlines()
    processes: list[dict] = []
    for line in lines[1:]:  # skip header row
        parts = line.split()
        if len(parts) < 9:
            continue
        # USER PID PPID VSIZE RSS WCHAN PC S NAME
        try:
            entry = {
                "user": parts[0],
                "pid": int(parts[1]),
                "name": parts[-1],
            }
        except (ValueError, IndexError):
            continue
        processes.append(entry)
        if len(processes) >= _MAX_PROCESSES:
            break

    return {"processes": processes, "serial": serial}


# ---------------------------------------------------------------------------
# Route 10 – GET /api/console/devices/{serial}/settings/{namespace}
# ---------------------------------------------------------------------------

_ALLOWED_NAMESPACES = {"system", "secure", "global"}


@router.get("/devices/{serial}/settings/{namespace}")
async def get_device_settings(
    request: Request,
    serial: str,
    namespace: str,
) -> dict:
    """Return all settings under *namespace* from *serial*."""
    guard = _require_console_action(request, serial)

    if namespace not in _ALLOWED_NAMESPACES:
        raise HTTPException(
            status_code=400,
            detail=f"Namespace must be one of: {', '.join(sorted(_ALLOWED_NAMESPACES))}",
        )

    try:
        code, stdout, _ = await _adb._exec_cmd(
            ["-s", serial, "shell", "settings", "list", namespace],
            timeout=20.0, output_limit=512 * 1024)
        if not guard():
            raise HTTPException(status_code=401, detail="Session or scope revoked")
        if code != 0:
            raise HTTPException(status_code=502, detail="Settings inventory unavailable")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Settings query timed out")
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("settings list failed (serial=%s, namespace=%s): %s", serial, namespace, exc)
        raise HTTPException(status_code=500, detail="Failed to retrieve device settings")

    settings: dict[str, str] = {}
    for line in stdout.decode(errors="replace").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            settings[key.strip()] = value.strip()

    return {"namespace": namespace, "serial": serial, "settings": settings}
