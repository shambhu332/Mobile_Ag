"""ADB device manager for MobileAg dynamic testing and orchestration."""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import shutil
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Optional

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ConnectedDevice:
    serial: str
    status: str
    model: str = "Unknown"
    android_version: str = "Unknown"
    sdk_level: str = "Unknown"
    is_emulator: bool = False
    is_rooted: bool = False


class ADBManager:
    """Manages ADB interactions with connected Android emulators and devices."""

    def __init__(self, adb_path: Optional[str] = None) -> None:
        self.adb_bin = adb_path or shutil.which("adb") or "adb"

    async def _exec_cmd(self, args: list[str], timeout: float = 3.0, output_limit: int | None = None) -> tuple[int, bytes, bytes]:
        """Execute an ADB command with strict timeout protection to prevent hanging on offline devices."""
        if "shell" in args:
            index = args.index("shell")
            if len(args[index + 1:]) > 1:
                args = args[:index + 1] + [shlex.join(args[index + 1:])]
        proc = None
        readers = []
        try:
            proc = await asyncio.create_subprocess_exec(
                self.adb_bin, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            if output_limit is None:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            else:
                async def bounded(stream):
                    data=bytearray()
                    while chunk:=await stream.read(16384):
                        if len(data)+len(chunk)>output_limit:raise ValueError("ADB output limit exceeded")
                        data.extend(chunk)
                    return bytes(data)
                readers=[asyncio.create_task(bounded(proc.stdout)),asyncio.create_task(bounded(proc.stderr))]
                async def finish():
                    result=await asyncio.gather(*readers)
                    await proc.wait()
                    return result
                stdout,stderr=await asyncio.wait_for(finish(),timeout=timeout)
            return proc.returncode or 0, stdout, stderr
        except asyncio.CancelledError:
            if proc and proc.returncode is None:
                proc.kill()
                await proc.wait()
            raise
        except asyncio.TimeoutError:
            if proc:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return -1, b"", b"ADB command timed out (device offline or not responding)"
        except Exception as e:
            if proc and proc.returncode is None:
                proc.kill()
                await proc.wait()
            return -1, b"", str(e).encode()
        finally:
            for reader in readers:
                if not reader.done():reader.cancel()
            if readers:await asyncio.gather(*readers,return_exceptions=True)

    async def is_adb_available(self) -> bool:
        """Check if ADB executable exists and can execute."""
        code, stdout, _ = await self._exec_cmd(["version"], timeout=2.0)
        return code == 0 and b"Android Debug Bridge" in stdout

    async def discover_devices(self) -> list[ConnectedDevice]:
        """Host inventory only: never run shell, probe root, connect or select a device."""
        code, stdout, _ = await self._exec_cmd(
            ["devices", "-l"], timeout=3.0, output_limit=65536)
        if code != 0:
            raise ValueError("ADB inventory unavailable")
        devices = []
        seen = set()
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 2 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", parts[0]):
                continue
            serial, status = parts[:2]
            if status not in {"device", "offline", "unauthorized", "recovery", "sideload", "bootloader", "no"} or serial in seen:
                continue
            seen.add(serial)
            model = next((part[6:128] for part in parts[2:] if part.startswith("model:")), "Unknown")
            devices.append(ConnectedDevice(serial=serial, status=status, model=model,
                                           is_emulator=serial.startswith("emulator-")))
            if len(devices) >= 100:
                break
        return devices

    async def list_devices(self, allowed_serials: set[str] | None = None) -> list[ConnectedDevice]:
        """Enumerate all connected Android devices and emulators."""
        devices: list[ConnectedDevice] = []
        code, stdout, _ = await self._exec_cmd(["devices", "-l"], timeout=3.0)
        if code != 0:
            return devices

        output = stdout.decode("utf-8", errors="replace")
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices") or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial, status = parts[0], parts[1]
                if status == "device" and (allowed_serials is None or serial in allowed_serials):
                    dev_info = await self._get_device_details(serial)
                    devices.append(dev_info)
                else:
                    devices.append(ConnectedDevice(serial=serial, status=status))
        return devices

    async def _get_device_details(self, serial: str) -> ConnectedDevice:
        """Fetch model, Android OS version, SDK level, and root status for a device."""
        model = await self._getprop(serial, "ro.product.model") or "Android Device"
        version = await self._getprop(serial, "ro.build.version.release") or "Unknown"
        sdk = await self._getprop(serial, "ro.build.version.sdk") or "Unknown"
        hardware = await self._getprop(serial, "ro.hardware")
        qemu = await self._getprop(serial, "ro.kernel.qemu")
        is_emu = (qemu == "1" or "emulator" in serial or
                  any(marker in hardware.lower() for marker in ("goldfish", "ranchu", "vbox")) or
                  "goldfish" in model.lower() or "sdk" in model.lower())
        is_root = await self._check_root(serial)

        return ConnectedDevice(
            serial=serial,
            status="online",
            model=model,
            android_version=version,
            sdk_level=sdk,
            is_emulator=is_emu,
            is_rooted=is_root
        )

    async def _getprop(self, serial: str, prop_name: str) -> str:
        code, stdout, _ = await self._exec_cmd(["-s", serial, "shell", "getprop", prop_name], timeout=2.0)
        if code == 0:
            return stdout.decode("utf-8", errors="replace").strip()
        return ""

    async def _check_root(self, serial: str) -> bool:
        """Observe the current ADB shell identity without invoking su or changing adbd.

        False means root was not observed, not that no escalation is possible.
        """
        code, stdout, _ = await self._exec_cmd(["-s", serial, "shell", "id"], timeout=2.0)
        if code == 0 and b"uid=0(root)" in stdout:
            return True

        return False

    async def connect_device(self, host_port: str, guard=None) -> dict[str, Any]:
        """Connect to a remote or local emulator/device via TCP (e.g. 127.0.0.1:5555)."""
        self._check_mutation_guard(guard)
        if not re.fullmatch(r'(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}', host_port) or int(host_port.rsplit(':', 1)[1]) > 65535:
            raise ValueError('Invalid ADB connect host/port')
        self._check_mutation_guard(guard)
        code, stdout, stderr = await self._exec_cmd(["connect", host_port], timeout=4.0)
        self._check_mutation_guard(guard)
        out_str = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()
        success = "connected to" in out_str.lower() or "already connected" in out_str.lower()
        return {"status": "success" if success else "failed", "output": out_str}

    async def restart_root(self, serial: str, guard=None) -> dict[str, Any]:
        """Restart adbd with root permissions on target device."""
        def check_scope():
            if not callable(guard):
                raise PermissionError("ADB root action requires an explicit scope guard")
            # Let scope-denial exceptions propagate unchanged (for example, a
            # web route's HTTP 403); any exception still stops before ADB.
            approved = guard()
            if inspect.isawaitable(approved):
                close = getattr(approved, "close", None)
                if callable(close):
                    close()
                raise PermissionError("ADB root action scope guard must be synchronous")
            if approved is False:
                raise PermissionError("ADB root action scope is unavailable or revoked")

        check_scope()
        code, stdout, stderr = await self._exec_cmd(["-s", serial, "root"], timeout=4.0)
        check_scope()
        out_str = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()
        is_root = await self._check_root(serial)
        check_scope()
        return {
            "status": "success" if is_root else "notice",
            "output": out_str or ("Root shell verified" if is_root else "adb root not supported in production build"),
            "is_rooted": is_root,
        }

    @staticmethod
    def _check_mutation_guard(guard) -> None:
        """Require a synchronous, current authorization check before device mutation."""
        if not callable(guard):
            raise PermissionError("ADB device mutation requires an explicit scope guard")
        approved = guard()
        if inspect.isawaitable(approved):
            close = getattr(approved, "close", None)
            if callable(close):
                close()
            raise PermissionError("ADB mutation scope guard must be synchronous")
        if approved is False:
            raise PermissionError("ADB mutation scope is unavailable or revoked")

    async def install_apk(self, serial: str, apk_path: str | Path, grant_permissions: bool = False, replace: bool = False, guard=None) -> dict[str, Any]:
        """Install an APK onto the target device, optionally auto-granting permissions."""
        self._check_mutation_guard(guard)
        apk_p = Path(apk_path).resolve()
        if not apk_p.exists():
            return {"status": "error", "message": f"APK not found: {apk_p}"}

        cmd = ["-s", serial, "install"]
        if replace:
            cmd.append("-r")
        if grant_permissions:
            cmd.append("-g")
        cmd.append(str(apk_p))

        self._check_mutation_guard(guard)
        code, stdout, stderr = await self._exec_cmd(cmd, timeout=30.0)
        self._check_mutation_guard(guard)
        out_str = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()
        success = code == 0 and "Success" in out_str
        return {
            "status": "success" if success else "failed",
            "output": out_str,
            "apk": apk_p.name
        }

    async def launch_activity(self, serial: str, component: str, guard=None) -> dict[str, Any]:
        """Launch an activity component (e.g. 'com.app/.MainActivity') via am start."""
        self._check_mutation_guard(guard)
        cmd = ["-s", serial, "shell", "am", "start", "-W", "-n", component]
        self._check_mutation_guard(guard)
        code, stdout, stderr = await self._exec_cmd(cmd, timeout=15.0)
        self._check_mutation_guard(guard)
        output = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()
        return {
            "status": "success" if code == 0 and not any(marker in output for marker in ("Error:", "Error type", "Exception", "Status: timeout")) else "failed",
            "output": output,
            "component": component
        }

    async def get_logcat_dump(self, serial: str, filter_pkg: Optional[str] = None, lines: int = 300,
                              pid: Optional[int] = None, guard=None) -> list[str]:
        """Retrieve the recent logcat buffer."""
        self._check_mutation_guard(guard)
        # The auditor requires PID/TID attribution. Android's default brief format
        # omits the structured fields and silently defeats target-process checks.
        cmd = ["-s", serial, "logcat", "-v", "threadtime", "-d", "-t", str(lines)]
        if pid is not None:
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
                raise ValueError('A positive process ID is required')
            cmd.append(f'--pid={pid}')
        self._check_mutation_guard(guard)
        code, stdout, _ = await self._exec_cmd(cmd, timeout=3.0)
        self._check_mutation_guard(guard)
        if code != 0:
            return []

        raw_lines = stdout.decode("utf-8", errors="replace").splitlines()
        # A package substring filter is neither an authorization boundary nor a
        # correct process filter (fatal frames usually contain only PID/TID).
        # Callers must attribute threadtime records to exact Process/PID records.
        return raw_lines

    async def get_process_pids(self, serial: str, package_name: str, guard=None) -> list[int]:
        """Return bounded numeric PIDs for an exact validated Android package."""
        self._check_mutation_guard(guard)
        if not re.fullmatch(r'[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+', package_name):
            raise ValueError('Invalid Android package name')
        self._check_mutation_guard(guard)
        code, stdout, _ = await self._exec_cmd(['-s', serial, 'shell', 'pidof', package_name], timeout=3.0)
        self._check_mutation_guard(guard)
        if code != 0:
            return []
        return list(dict.fromkeys(int(token) for token in stdout.decode('ascii', errors='ignore').split()
                                  if token.isdecimal() and 0 < int(token) < 2**31))[:8]

    async def clear_logcat(self, serial: str) -> bool:
        """Clear the device logcat buffer."""
        code, _, _ = await self._exec_cmd(["-s", serial, "logcat", "-c"], timeout=3.0)
        return code == 0

    async def capture_screenshot(self, serial: str, guard=None) -> Optional[bytes]:
        """Capture device screenshot and return PNG bytes."""
        self._check_mutation_guard(guard)
        code, stdout, _ = await self._exec_cmd(["-s", serial, "exec-out", "screencap", "-p"], timeout=5.0)
        self._check_mutation_guard(guard)
        if code == 0 and stdout.startswith(b"\x89PNG"):
            return stdout
        return None

    async def execute_shell(self, serial: str, command: str, guard=None) -> dict[str, Any]:
        """Execute an arbitrary adb shell command on target device."""
        self._check_mutation_guard(guard)
        cmd_parts = ["-s", serial, "shell", str(command)]
        self._check_mutation_guard(guard)
        code, stdout, stderr = await self._exec_cmd(cmd_parts, timeout=10.0)
        self._check_mutation_guard(guard)
        out_str = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()
        return {
            "status": "success" if code == 0 else "failed",
            "output": out_str or "(Command executed with no output)",
            "exit_code": code,
        }
