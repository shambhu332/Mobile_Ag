"""ADB device manager for MobileAg dynamic testing and orchestration."""

from __future__ import annotations

import asyncio
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

    async def connect_device(self, host_port: str) -> dict[str, Any]:
        """Connect to a remote or local emulator/device via TCP (e.g. 127.0.0.1:5555)."""
        code, stdout, stderr = await self._exec_cmd(["connect", host_port], timeout=4.0)
        out_str = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()
        success = "connected to" in out_str.lower() or "already connected" in out_str.lower()
        return {"status": "success" if success else "failed", "output": out_str}

    async def restart_root(self, serial: str) -> dict[str, Any]:
        """Restart adbd with root permissions on target device."""
        code, stdout, stderr = await self._exec_cmd(["-s", serial, "root"], timeout=4.0)
        out_str = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()
        is_root = await self._check_root(serial)
        return {
            "status": "success" if is_root else "notice",
            "output": out_str or ("Root shell verified" if is_root else "adb root not supported in production build"),
            "is_rooted": is_root,
        }

    async def install_apk(self, serial: str, apk_path: str | Path, grant_permissions: bool = True) -> dict[str, Any]:
        """Install an APK onto the target device, optionally auto-granting permissions."""
        apk_p = Path(apk_path).resolve()
        if not apk_p.exists():
            return {"status": "error", "message": f"APK not found: {apk_p}"}

        cmd = ["-s", serial, "install", "-r"]
        if grant_permissions:
            cmd.append("-g")
        cmd.append(str(apk_p))

        code, stdout, stderr = await self._exec_cmd(cmd, timeout=30.0)
        out_str = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()
        success = code == 0 and "Success" in out_str
        return {
            "status": "success" if success else "failed",
            "output": out_str,
            "apk": apk_p.name
        }

    async def launch_activity(self, serial: str, component: str) -> dict[str, Any]:
        """Launch an activity component (e.g. 'com.app/.MainActivity') via am start."""
        cmd = ["-s", serial, "shell", "am", "start", "-W", "-n", component]
        code, stdout, stderr = await self._exec_cmd(cmd, timeout=15.0)
        output = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()
        return {
            "status": "success" if code == 0 and not any(marker in output for marker in ("Error:", "Error type", "Exception", "Status: timeout")) else "failed",
            "output": output,
            "component": component
        }

    async def get_logcat_dump(self, serial: str, filter_pkg: Optional[str] = None, lines: int = 300) -> list[str]:
        """Retrieve the recent logcat buffer."""
        cmd = ["-s", serial, "logcat", "-d", "-t", str(lines)]
        code, stdout, _ = await self._exec_cmd(cmd, timeout=3.0)
        if code != 0:
            return []

        raw_lines = stdout.decode("utf-8", errors="replace").splitlines()
        if filter_pkg:
            return [l for l in raw_lines if filter_pkg in l]
        return raw_lines

    async def clear_logcat(self, serial: str) -> bool:
        """Clear the device logcat buffer."""
        code, _, _ = await self._exec_cmd(["-s", serial, "logcat", "-c"], timeout=3.0)
        return code == 0

    async def capture_screenshot(self, serial: str) -> Optional[bytes]:
        """Capture device screenshot and return PNG bytes."""
        code, stdout, _ = await self._exec_cmd(["-s", serial, "exec-out", "screencap", "-p"], timeout=5.0)
        if code == 0 and stdout.startswith(b"\x89PNG"):
            return stdout
        return None

    async def execute_shell(self, serial: str, command: str) -> dict[str, Any]:
        """Execute an arbitrary adb shell command on target device."""
        cmd_parts = ["-s", serial, "shell", str(command)]
        code, stdout, stderr = await self._exec_cmd(cmd_parts, timeout=10.0)
        out_str = (stdout.decode("utf-8", errors="replace") + stderr.decode("utf-8", errors="replace")).strip()
        return {
            "status": "success" if code == 0 else "failed",
            "output": out_str or "(Command executed with no output)",
            "exit_code": code,
        }

