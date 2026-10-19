"""ADB device manager for MobileAg dynamic testing and orchestration."""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import shutil
import shlex
import socket
import struct
import xml.etree.ElementTree as ET
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

    async def installed_apk_identity(self, serial: str, package_name: str, expected_sha256: str,
                                     guard=None) -> dict[str, Any]:
        """Read-only, best-effort identity check for the installed APK set.

        This intentionally uses ordinary ADB shell access only (never ``su``).
        A match is valid only when exactly one installed APK hashes to the
        analyzed APK; split installs are reported as non-matching because a
        single uploaded APK cannot attest the complete installed artifact set.
        """
        self._check_mutation_guard(guard)
        if not re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+", package_name):
            raise ValueError("Invalid Android package name")
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", expected_sha256):
            raise ValueError("Invalid expected SHA-256")
        code, stdout, _ = await self._exec_cmd(
            ["-s", serial, "shell", "pm", "path", package_name], timeout=10.0, output_limit=16384)
        self._check_mutation_guard(guard)
        if code != 0:
            return {"status": "unavailable", "reason": "installed package paths could not be read", "apk_count": 0}
        paths = []
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            match = re.fullmatch(r"package:(/[^\s\x00]+)", line.strip())
            if match:
                paths.append(match.group(1))
        if not paths or len(paths) > 32:
            return {"status": "unavailable", "reason": "package path inventory was empty or exceeded limits", "apk_count": len(paths)}
        if len(paths) != 1:
            return {"status": "mismatch", "apk_count": len(paths), "installed_sha256": None,
                    "reason": "installed package is split; complete split artifacts were not attested"}
        hashes = []
        for path in paths:
            # Paths originate from Package Manager, but quote and constrain them
            # anyway before crossing the shell boundary.
            if not re.fullmatch(r"/[A-Za-z0-9_./@+=,-]+", path) or ".." in path.split("/"):
                return {"status": "unavailable", "reason": "package manager returned an unsafe path", "apk_count": len(paths)}
            self._check_mutation_guard(guard)
            code, data, _ = await self._exec_cmd(
                ["-s", serial, "shell", "sha256sum", path], timeout=20.0, output_limit=4096)
            self._check_mutation_guard(guard)
            match = re.match(rb"^([A-Fa-f0-9]{64})\s+", data)
            if code != 0 or not match:
                return {"status": "unavailable", "reason": "installed APK content could not be hashed", "apk_count": len(paths)}
            hashes.append(match.group(1).decode("ascii").lower())
        matched = len(hashes) == 1 and hashes[0] == expected_sha256.lower()
        return {"status": "matched" if matched else "mismatch", "apk_count": len(hashes),
                "installed_sha256": hashes[0] if len(hashes) == 1 else None,
                "reason": None if matched else ("installed APK hash differs from the analyzed artifact" if len(hashes) == 1 else "installed package is split; complete split artifacts were not attested")}

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
        """Retired: preserve device log evidence; no command is issued."""
        raise PermissionError("Device-wide logcat clearing is disabled to preserve assessment evidence")

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

    @staticmethod
    def _decode_proc_net_addr(hex_addr: str) -> str:
        """Decode hex address from /proc/net/tcp format ('0100007F:0050' -> '127.0.0.1:80')."""
        if ":" not in hex_addr:
            return hex_addr
        ip_hex, port_hex = hex_addr.split(":", 1)
        try:
            port = int(port_hex, 16)
        except ValueError:
            port = 0
        port_str = "*" if port == 0 else str(port)

        try:
            if len(ip_hex) == 8:
                ip_bytes = bytes.fromhex(ip_hex)
                ip = socket.inet_ntoa(ip_bytes[::-1])
                return f"{ip}:{port_str}"
            elif len(ip_hex) == 32:
                raw = bytes.fromhex(ip_hex)
                words = [raw[i:i + 4][::-1] for i in range(0, 32, 4)]
                ip = socket.inet_ntop(socket.AF_INET6, b"".join(words))
                return f"[{ip}]:{port_str}" if ip != "::" else f":::{port_str}"
        except Exception:
            pass
        return f"{ip_hex}:{port_str}"

    async def get_sockets(self, serial: str, guard=None) -> list[dict[str, Any]]:
        """Retrieve active network socket table (TCP/TCP6/UDP) from device."""
        self._check_mutation_guard(guard)
        tcp_states = {
            "01": "ESTAB", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
            "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
            "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"
        }
        sockets: list[dict[str, Any]] = []

        for proto, proc_file in [("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"), ("udp", "/proc/net/udp")]:
            self._check_mutation_guard(guard)
            code, stdout, _ = await self._exec_cmd(["-s", serial, "shell", "cat", proc_file], timeout=3.0)
            self._check_mutation_guard(guard)
            if code != 0:
                continue

            lines = stdout.decode("utf-8", errors="replace").splitlines()
            for line in lines[1:]:  # skip header
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                local_raw = parts[1]
                rem_raw = parts[2]
                st_hex = parts[3].upper()
                uid_raw = parts[7]
                inode_raw = parts[9]

                state_label = tcp_states.get(st_hex, "UNKNOWN") if proto.startswith("tcp") else "UNCONN"
                local_addr = self._decode_proc_net_addr(local_raw)
                peer_addr = self._decode_proc_net_addr(rem_raw)

                try:
                    uid = int(uid_raw)
                except ValueError:
                    uid = -1

                sockets.append({
                    "proto": proto,
                    "state": state_label,
                    "local": local_addr,
                    "peer": peer_addr,
                    "proc": f"uid:{uid}" if uid >= 0 else "system",
                    "uid": uid,
                    "inode": inode_raw,
                })
                if len(sockets) >= 500:
                    break
            if len(sockets) >= 500:
                break

        return sockets

    async def dump_view_hierarchy(self, serial: str, guard=None) -> dict[str, Any]:
        """Dump and parse live view hierarchy from device via uiautomator dump."""
        self._check_mutation_guard(guard)
        remote_xml = "/data/local/tmp/uidump.xml"
        cmd = ["-s", serial, "shell", "uiautomator", "dump", remote_xml]
        self._check_mutation_guard(guard)
        code, stdout, stderr = await self._exec_cmd(cmd, timeout=8.0)
        self._check_mutation_guard(guard)

        cat_cmd = ["-s", serial, "shell", "cat", remote_xml]
        self._check_mutation_guard(guard)
        cat_code, cat_stdout, _ = await self._exec_cmd(cat_cmd, timeout=5.0)
        self._check_mutation_guard(guard)
        await self._exec_cmd(["-s", serial, "shell", "rm", "-f", remote_xml], timeout=2.0)

        if cat_code != 0 or not cat_stdout:
            return {"nodes": [], "count": 0, "status": "unavailable", "output": stdout.decode("utf-8", errors="replace")}

        nodes: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(cat_stdout.decode("utf-8", errors="replace"))

            def walk(el: ET.Element, depth: int):
                node_id = f"node_{len(nodes)}"
                full_cls = el.attrib.get("class", "")
                short_cls = full_cls.split(".")[-1] if full_cls else "View"
                nodes.append({
                    "id": node_id,
                    "cls": short_cls,
                    "fullClass": full_cls,
                    "rid": el.attrib.get("resource-id", ""),
                    "text": el.attrib.get("text", ""),
                    "desc": el.attrib.get("content-desc", ""),
                    "bounds": el.attrib.get("bounds", ""),
                    "clickable": el.attrib.get("clickable", "false"),
                    "focusable": el.attrib.get("focusable", "false"),
                    "enabled": el.attrib.get("enabled", "true"),
                    "pkg": el.attrib.get("package", ""),
                    "depth": depth,
                })
                for child in el:
                    walk(child, depth + 1)

            for child in root:
                walk(child, 0)
        except Exception as exc:
            logger.debug(f"Error parsing uiautomator XML: {exc}")
            return {"nodes": [], "count": 0, "status": "parse_error", "error": str(exc)}

        return {"nodes": nodes, "count": len(nodes), "status": "success"}

    async def get_settings(self, serial: str, namespace: str = "global", key: Optional[str] = None, guard=None) -> list[dict[str, str]]:
        """Read Android system / secure / global settings."""
        self._check_mutation_guard(guard)
        if namespace not in ("system", "secure", "global"):
            raise ValueError(f"Invalid settings namespace: {namespace}")

        if key:
            code, stdout, _ = await self._exec_cmd(["-s", serial, "shell", "settings", "get", namespace, key], timeout=3.0)
            self._check_mutation_guard(guard)
            val = stdout.decode("utf-8", errors="replace").strip()
            return [{"k": key, "v": val if code == 0 else ""}]

        code, stdout, _ = await self._exec_cmd(["-s", serial, "shell", "settings", "list", namespace], timeout=5.0)
        self._check_mutation_guard(guard)
        results: list[dict[str, str]] = []
        if code == 0:
            for line in stdout.decode("utf-8", errors="replace").splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    results.append({"k": k.strip(), "v": v.strip()})
        return results

    async def put_setting(self, serial: str, namespace: str, key: str, value: str, guard=None) -> dict[str, Any]:
        """Write Android setting via settings put <namespace> <key> <value>."""
        self._check_mutation_guard(guard)
        if namespace not in ("system", "secure", "global"):
            raise ValueError(f"Invalid settings namespace: {namespace}")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
            raise ValueError("Invalid setting key format")

        cmd = ["-s", serial, "shell", "settings", "put", namespace, key, str(value)]
        self._check_mutation_guard(guard)
        code, stdout, stderr = await self._exec_cmd(cmd, timeout=4.0)
        self._check_mutation_guard(guard)
        success = code == 0
        return {
            "status": "success" if success else "failed",
            "namespace": namespace,
            "key": key,
            "value": value,
            "output": (stdout + stderr).decode("utf-8", errors="replace").strip(),
        }

    async def delete_setting(self, serial: str, namespace: str, key: str, guard=None) -> dict[str, Any]:
        """Delete Android setting via settings delete <namespace> <key>."""
        self._check_mutation_guard(guard)
        if namespace not in ("system", "secure", "global"):
            raise ValueError(f"Invalid settings namespace: {namespace}")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
            raise ValueError("Invalid setting key format")

        cmd = ["-s", serial, "shell", "settings", "delete", namespace, key]
        self._check_mutation_guard(guard)
        code, stdout, stderr = await self._exec_cmd(cmd, timeout=4.0)
        self._check_mutation_guard(guard)
        return {
            "status": "success" if code == 0 else "failed",
            "namespace": namespace,
            "key": key,
            "output": (stdout + stderr).decode("utf-8", errors="replace").strip(),
        }

    async def configure_proxy(self, serial: str, host: str, port: int, guard=None) -> dict[str, Any]:
        """Configure device global HTTP proxy for network interception."""
        self._check_mutation_guard(guard)
        if not re.fullmatch(r"[A-Za-z0-9.-]+", host) or not (1 <= port <= 65535):
            raise ValueError("Invalid proxy host or port")

        proxy_str = f"{host}:{port}"
        await self.put_setting(serial, "global", "http_proxy", proxy_str, guard=guard)
        await self.put_setting(serial, "global", "global_http_proxy_host", host, guard=guard)
        await self.put_setting(serial, "global", "global_http_proxy_port", str(port), guard=guard)
        return {"status": "success", "proxy": proxy_str}

    async def clear_proxy(self, serial: str, guard=None) -> dict[str, Any]:
        """Clear device global HTTP proxy."""
        self._check_mutation_guard(guard)
        await self.put_setting(serial, "global", "http_proxy", ":0", guard=guard)
        await self.delete_setting(serial, "global", "http_proxy", guard=guard)
        await self.delete_setting(serial, "global", "global_http_proxy_host", guard=guard)
        await self.delete_setting(serial, "global", "global_http_proxy_port", guard=guard)
        return {"status": "success", "proxy": "cleared"}

    async def get_clipboard(self, serial: str, guard=None) -> dict[str, Any]:
        """Retrieve current system clipboard text from Android device."""
        self._check_mutation_guard(guard)
        code, stdout, _ = await self._exec_cmd(["-s", serial, "shell", "cmd clipboard get"], timeout=3.0)
        self._check_mutation_guard(guard)
        text = stdout.decode("utf-8", errors="replace").strip()
        if code == 0 and text:
            return {"status": "success", "text": text}
        code, stdout, stderr = await self._exec_cmd(["-s", serial, "shell", "service call clipboard 2 i32 1 s16 com.android.shell"], timeout=3.0)
        self._check_mutation_guard(guard)
        raw = (stdout + stderr).decode("utf-8", errors="replace").strip()
        return {"status": "success" if code == 0 else "failed", "text": raw}

    async def set_clipboard(self, serial: str, text: str, guard=None) -> dict[str, Any]:
        """Inject text into current system clipboard on Android device."""
        self._check_mutation_guard(guard)
        quoted = shlex.quote(text)
        code, stdout, stderr = await self._exec_cmd(["-s", serial, "shell", f"cmd clipboard set {quoted}"], timeout=3.0)
        self._check_mutation_guard(guard)
        return {"status": "success" if code == 0 else "failed", "output": (stdout + stderr).decode("utf-8", errors="replace").strip()}

    async def get_package_info(self, serial: str, package_name: str, guard=None) -> dict[str, Any]:
        """Query package metadata, permissions, code paths, and components via dumpsys package."""
        self._check_mutation_guard(guard)
        if not re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+", package_name):
            raise ValueError("Invalid package name format")

        code, stdout, stderr = await self._exec_cmd(["-s", serial, "shell", f"dumpsys package {shlex.quote(package_name)}"], timeout=10.0, output_limit=512*1024)
        self._check_mutation_guard(guard)
        raw = stdout.decode("utf-8", errors="replace")

        version_name = "Unknown"
        version_code = "Unknown"
        target_sdk = "Unknown"
        min_sdk = "Unknown"
        data_dir = "Unknown"
        code_path = "Unknown"
        requested_permissions: list[str] = []
        granted_permissions: list[str] = []

        in_req_perms = False
        in_install_perms = False

        for line in raw.splitlines():
            sline = line.strip()
            if "versionName=" in sline:
                m = re.search(r"versionName=([^\s]+)", sline)
                if m:
                    version_name = m.group(1)
            if "versionCode=" in sline:
                m = re.search(r"versionCode=([0-9]+)", sline)
                if m:
                    version_code = m.group(1)
            if "targetSdk=" in sline:
                m = re.search(r"targetSdk=([0-9]+)", sline)
                if m:
                    target_sdk = m.group(1)
            if "minSdk=" in sline:
                m = re.search(r"minSdk=([0-9]+)", sline)
                if m:
                    min_sdk = m.group(1)
            if "dataDir=" in sline:
                m = re.search(r"dataDir=([^\s]+)", sline)
                if m:
                    data_dir = m.group(1)
            if "codePath=" in sline:
                m = re.search(r"codePath=([^\s]+)", sline)
                if m:
                    code_path = m.group(1)

            if sline == "requested permissions:":
                in_req_perms = True
                in_install_perms = False
                continue
            elif sline.startswith("install permissions:") or sline.startswith("runtime permissions:"):
                in_req_perms = False
                in_install_perms = True
                continue
            elif sline.endswith(":") and not sline.startswith("android."):
                in_req_perms = False
                in_install_perms = False

            if in_req_perms and sline.startswith("android.permission."):
                perm = sline.split(":")[0].strip()
                if perm not in requested_permissions:
                    requested_permissions.append(perm)
            elif in_install_perms and "android.permission." in sline:
                m = re.search(r"(android\.permission\.[A-Za-z0-9_]+): granted=true", sline)
                if m and m.group(1) not in granted_permissions:
                    granted_permissions.append(m.group(1))

        return {
            "package_name": package_name,
            "version_name": version_name,
            "version_code": version_code,
            "target_sdk": target_sdk,
            "min_sdk": min_sdk,
            "data_dir": data_dir,
            "code_path": code_path,
            "requested_permissions": requested_permissions,
            "granted_permissions": granted_permissions,
            "dangerous_count": sum(1 for p in requested_permissions if any(d in p for d in ["CAMERA", "LOCATION", "STORAGE", "AUDIO", "CONTACTS", "SMS", "PHONE"])),
        }

    async def execute_package_action(self, serial: str, package_name: str, action: str, guard=None) -> dict[str, Any]:
        """Perform package lifecycle action: force_stop, clear_data, launch, uninstall."""
        self._check_mutation_guard(guard)
        if not re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+", package_name):
            raise ValueError("Invalid package name format")
        if action not in ("force_stop", "clear_data", "launch", "uninstall"):
            raise ValueError(f"Unsupported package action: {action}")

        pkg = shlex.quote(package_name)
        if action == "force_stop":
            cmd = f"am force-stop {pkg}"
        elif action == "clear_data":
            cmd = f"pm clear {pkg}"
        elif action == "launch":
            cmd = f"monkey -p {pkg} -c android.intent.category.LAUNCHER 1"
        else:
            cmd = f"pm uninstall {pkg}"

        code, stdout, stderr = await self._exec_cmd(["-s", serial, "shell", cmd], timeout=10.0)
        self._check_mutation_guard(guard)
        out = (stdout + stderr).decode("utf-8", errors="replace").strip()
        return {
            "status": "success" if code == 0 else "failed",
            "action": action,
            "package_name": package_name,
            "output": out or "Done",
        }

    async def get_device_posture(self, serial: str, guard=None) -> dict[str, Any]:
        """Comprehensive security posture assessment of connected device."""
        self._check_mutation_guard(guard)
        prop_cmd = (
            "getprop ro.build.version.release; echo '---'; "
            "getprop ro.build.version.sdk; echo '---'; "
            "getprop ro.product.model; echo '---'; "
            "getprop ro.product.manufacturer; echo '---'; "
            "getprop ro.product.cpu.abi; echo '---'; "
            "getprop ro.build.version.security_patch; echo '---'; "
            "getprop ro.build.type; echo '---'; "
            "getprop ro.build.tags; echo '---'; "
            "getprop ro.debuggable; echo '---'; "
            "getenforce 2>/dev/null || echo 'Unknown'; echo '---'; "
            "which su 2>/dev/null || echo 'none'"
        )
        code, stdout, _ = await self._exec_cmd(["-s", serial, "shell", prop_cmd], timeout=8.0)
        self._check_mutation_guard(guard)
        raw_parts = [p.strip() for p in stdout.decode("utf-8", errors="replace").split("---")]

        release = raw_parts[0] if len(raw_parts) > 0 and raw_parts[0] else "Unknown"
        sdk = raw_parts[1] if len(raw_parts) > 1 and raw_parts[1] else "Unknown"
        model = raw_parts[2] if len(raw_parts) > 2 and raw_parts[2] else "Android Device"
        manufacturer = raw_parts[3] if len(raw_parts) > 3 and raw_parts[3] else "Generic"
        abi = raw_parts[4] if len(raw_parts) > 4 and raw_parts[4] else "arm64-v8a"
        patch = raw_parts[5] if len(raw_parts) > 5 and raw_parts[5] else "Unknown"
        build_type = raw_parts[6] if len(raw_parts) > 6 and raw_parts[6] else "user"
        tags = raw_parts[7] if len(raw_parts) > 7 and raw_parts[7] else "release-keys"
        debuggable = raw_parts[8] == "1" if len(raw_parts) > 8 else False
        selinux = raw_parts[9] if len(raw_parts) > 9 and raw_parts[9] else "Enforcing"
        su_path = raw_parts[10] if len(raw_parts) > 10 and raw_parts[10] != "none" else None

        is_rooted = bool(su_path or tags == "test-keys" or debuggable)
        is_permissive = selinux.lower() in ("permissive", "disabled")

        score = 100
        findings = []
        if is_permissive:
            score -= 35
            findings.append({
                "severity": "CRITICAL",
                "title": "SELinux Enforce Disabled / Permissive",
                "detail": f"Device SELinux is set to '{selinux}'. Mandatory Access Control (MAC) protections are bypassed.",
                "recommendation": "Execute 'setenforce 1' on production devices to re-enable kernel MAC isolation."
            })
        if is_rooted:
            score -= 30
            findings.append({
                "severity": "HIGH",
                "title": "Device Root / Superuser Access Detected",
                "detail": f"Superuser binary found at '{su_path or tags}'. App sandbox integrity cannot be guaranteed.",
                "recommendation": "Perform security audits on non-rooted production firmware to assess real-world defenses."
            })
        if debuggable:
            score -= 15
            findings.append({
                "severity": "MEDIUM",
                "title": "Android System Build Marked Debuggable (ro.debuggable=1)",
                "detail": "Any application on this device can be attached and inspected via JDWP without run-as restrictions.",
                "recommendation": "Deploy release builds (ro.debuggable=0) for client testing."
            })
        if tags == "test-keys":
            score -= 10
            findings.append({
                "severity": "MEDIUM",
                "title": "Firmware Signed with Public Test Keys",
                "detail": "The OS build uses AOSP public test-keys rather than vendor private release keys.",
                "recommendation": "Ensure production devices are signed with hardware OEM release keys."
            })
        if patch != "Unknown":
            try:
                year = int(patch.split("-")[0])
                if year < 2024:
                    score -= 15
                    findings.append({
                        "severity": "HIGH",
                        "title": f"Outdated Android Security Patch Level ({patch})",
                        "detail": f"Device security patch date is {patch}, leaving device vulnerable to known Android CVEs.",
                        "recommendation": "Update device firmware to the latest available security patch level."
                    })
            except Exception:
                pass

        score = max(10, score)
        return {
            "serial": serial,
            "model": model,
            "manufacturer": manufacturer,
            "android_version": release,
            "sdk_level": sdk,
            "abi": abi,
            "security_patch": patch,
            "build_type": build_type,
            "build_tags": tags,
            "debuggable": debuggable,
            "selinux": selinux,
            "is_rooted": is_rooted,
            "is_permissive": is_permissive,
            "su_path": su_path,
            "posture_score": score,
            "findings": findings,
        }

    async def wireless_mdns_services(self, guard=None) -> dict[str, Any]:
        """Discover wireless ADB targets via mDNS."""
        self._check_mutation_guard(guard)
        code, stdout, stderr = await self._exec_cmd(["mdns", "services"], timeout=10.0)
        self._check_mutation_guard(guard)
        services = []
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or "List of" in line:
                continue
            m = re.match(r"^(\S+)\s+(_\S+\._tcp\.?)\s+(\S+:\d+)$", line)
            if m:
                services.append({
                    "name": m.group(1),
                    "type": m.group(2).rstrip("."),
                    "addr": m.group(3),
                })
        return {
            "status": "success",
            "services": services,
            "raw": stdout.decode("utf-8", errors="replace").strip(),
        }

    async def wireless_pair(self, addr: str, code: str, guard=None) -> dict[str, Any]:
        """Pair with wireless Android 11+ device via IP:Port and pairing code."""
        self._check_mutation_guard(guard)
        if not re.fullmatch(r"[\w.-]+:\d+", addr):
            raise ValueError("Address must be host:port")
        if not re.fullmatch(r"\d{4,8}", code.strip()):
            raise ValueError("Pairing code must be 4 to 8 digits")

        ret, stdout, stderr = await self._exec_cmd(["pair", addr, code.strip()], timeout=30.0)
        self._check_mutation_guard(guard)
        out = (stdout + stderr).decode("utf-8", errors="replace").strip()
        success = ret == 0 and "success" in out.lower()
        return {
            "status": "success" if success else "failed",
            "output": out or ("Successfully paired to " + addr if success else "Pairing failed"),
        }

    async def wireless_connect(self, addr: str, guard=None) -> dict[str, Any]:
        """Connect to wireless ADB target."""
        self._check_mutation_guard(guard)
        if not re.fullmatch(r"[\w.-]+(?::\d+)?", addr):
            raise ValueError("Address must be host or host:port")

        ret, stdout, stderr = await self._exec_cmd(["connect", addr], timeout=20.0)
        self._check_mutation_guard(guard)
        out = (stdout + stderr).decode("utf-8", errors="replace").strip()
        success = ret == 0 and "connected to" in out.lower()
        return {
            "status": "success" if success else "failed",
            "output": out or ("Connected to " + addr if success else "Connection failed"),
        }

    async def wireless_disconnect(self, addr: str, guard=None) -> dict[str, Any]:
        """Disconnect wireless ADB target."""
        self._check_mutation_guard(guard)
        if not re.fullmatch(r"[\w.-]+(?::\d+)?", addr):
            raise ValueError("Address must be host or host:port")

        ret, stdout, stderr = await self._exec_cmd(["disconnect", addr], timeout=10.0)
        self._check_mutation_guard(guard)
        out = (stdout + stderr).decode("utf-8", errors="replace").strip()
        return {
            "status": "success",
            "output": out or "Disconnected",
        }

    def prepare_ca_certificate(self, raw_bytes: bytes) -> dict[str, Any]:
        """Turn PEM or DER CA certificate into Android trust-store format (<hash>.0)."""
        import tempfile
        import subprocess

        openssl_bin = shutil.which("openssl") or "/usr/bin/openssl"
        with tempfile.TemporaryDirectory(prefix="mobileag-ca-") as tmpdir:
            in_file = Path(tmpdir) / "cert.in"
            pem_file = Path(tmpdir) / "cert.pem"
            in_file.write_bytes(raw_bytes)

            form = "PEM"
            res = subprocess.run([openssl_bin, "x509", "-inform", "PEM", "-in", str(in_file), "-noout"], capture_output=True)
            if res.returncode != 0:
                form = "DER"

            conv = subprocess.run([openssl_bin, "x509", "-inform", form, "-in", str(in_file), "-outform", "PEM", "-out", str(pem_file)], capture_output=True)
            if conv.returncode != 0:
                raise ValueError("Invalid certificate format (requires valid PEM or DER X.509 CA certificate)")

            hash_res = subprocess.run([openssl_bin, "x509", "-in", str(pem_file), "-subject_hash_old", "-noout"], capture_output=True, text=True)
            subj_hash = hash_res.stdout.strip().splitlines()[0] if hash_res.stdout.strip() else ""
            if not re.fullmatch(r"[0-9a-fA-F]{8}", subj_hash):
                raise ValueError(f"Could not compute Android subject hash from certificate: {hash_res.stderr}")

            subj_res = subprocess.run([openssl_bin, "x509", "-in", str(pem_file), "-subject", "-noout"], capture_output=True, text=True)
            subject = subj_res.stdout.strip().replace("subject=", "").strip()

            issuer_res = subprocess.run([openssl_bin, "x509", "-in", str(pem_file), "-issuer", "-noout"], capture_output=True, text=True)
            issuer = issuer_res.stdout.strip().replace("issuer=", "").strip()

            dates_res = subprocess.run([openssl_bin, "x509", "-in", str(pem_file), "-dates", "-noout"], capture_output=True, text=True)
            dates = dates_res.stdout.strip()

            pem_content = pem_file.read_text(encoding="utf-8")
            android_filename = f"{subj_hash.lower()}.0"

            return {
                "hash": subj_hash.lower(),
                "android_filename": android_filename,
                "subject": subject,
                "issuer": issuer,
                "dates": dates,
                "pem": pem_content,
            }

    async def install_ca_certificate(self, serial: str, cert_pem: str, filename: str, guard=None) -> dict[str, Any]:
        """Stage CA certificate on device /data/local/tmp/ and guide trust installation."""
        self._check_mutation_guard(guard)
        if not re.fullmatch(r"[0-9a-fA-F]{8}\.0", filename):
            raise ValueError("Invalid Android CA filename (must be <hash>.0)")

        import tempfile
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tf:
            tf.write(cert_pem)
            tpath = tf.name

        target_path = f"/data/local/tmp/{filename}"
        code, stdout, stderr = await self._exec_cmd(["-s", serial, "push", tpath, target_path], timeout=15.0)
        self._check_mutation_guard(guard)
        try:
            Path(tpath).unlink(missing_ok=True)
        except Exception:
            pass

        if code != 0:
            raise RuntimeError(f"Failed to push CA cert to device: {stderr.decode('utf-8', errors='replace')}")

        await self._exec_cmd(["-s", serial, "shell", f"chmod 644 {target_path}"], timeout=5.0)

        return {
            "status": "staged",
            "serial": serial,
            "target_path": target_path,
            "filename": filename,
            "instructions": {
                "user_install": f"adb shell am start -a android.credentials.INSTALL -t application/x-x509-ca-cert -d file://{target_path}",
                "root_system_install": f"adb shell su -c 'mount -o rw,remount / && cp {target_path} /system/etc/security/cacerts/{filename} && chmod 644 /system/etc/security/cacerts/{filename}'",
                "magisk_overlay": "Install 'MagiskTrustUserCerts' module to automatically promote user CA to system trust store."
            }
        }

    async def get_package_memory_and_procs(self, serial: str, package_name: str, guard=None) -> dict[str, Any]:
        """Inspect live memory usage and process telemetry for a target package."""
        self._check_mutation_guard(guard)
        if not re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+", package_name):
            raise ValueError("Invalid package name format")

        code, stdout, _ = await self._exec_cmd(["-s", serial, "shell", f"dumpsys meminfo {shlex.quote(package_name)}"], timeout=10.0)
        self._check_mutation_guard(guard)
        mem_text = stdout.decode("utf-8", errors="replace")

        native_heap = 0
        java_heap = 0
        code_mem = 0
        stack_mem = 0
        graphics_mem = 0
        private_dirty = 0
        total_pss = 0
        pid = None

        pid_match = re.search(r"MEMINFO in pid\s+(\d+)", mem_text)
        if pid_match:
            pid = int(pid_match.group(1))

        for line in mem_text.splitlines():
            s = line.strip()
            if "Native Heap" in s:
                nums = re.findall(r"\d+", s)
                if nums:
                    native_heap = int(nums[0])
            elif "Dalvik Heap" in s or "Java Heap" in s:
                nums = re.findall(r"\d+", s)
                if nums:
                    java_heap = int(nums[0])
            elif ".dex mmap" in s or ".so mmap" in s:
                nums = re.findall(r"\d+", s)
                if nums:
                    code_mem += int(nums[0])
            elif "Stack" in s:
                nums = re.findall(r"\d+", s)
                if nums:
                    stack_mem = int(nums[0])
            elif "GL mmap" in s or "Graphics" in s:
                nums = re.findall(r"\d+", s)
                if nums:
                    graphics_mem = int(nums[0])
            elif "TOTAL PSS:" in s or "TOTAL:" in s:
                nums = re.findall(r"\d+", s)
                if len(nums) >= 2:
                    total_pss = int(nums[0])
                    private_dirty = int(nums[1])

        ps_code, ps_out, _ = await self._exec_cmd(["-s", serial, "shell", f"ps -A | grep {shlex.quote(package_name)}"], timeout=5.0)
        processes = []
        for line in ps_out.decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 9 and package_name in parts[-1]:
                processes.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "ppid": parts[2],
                    "vsz": parts[4],
                    "rss": parts[5],
                    "name": parts[-1],
                })

        return {
            "package_name": package_name,
            "pid": pid or (processes[0]["pid"] if processes else None),
            "total_pss_kb": total_pss,
            "native_heap_kb": native_heap,
            "java_heap_kb": java_heap,
            "code_kb": code_mem,
            "stack_kb": stack_mem,
            "graphics_kb": graphics_mem,
            "private_dirty_kb": private_dirty,
            "active_processes": processes,
            "is_running": bool(pid or processes),
        }

    async def list_forwards(self, serial: str, guard: Optional[callable] = None) -> dict[str, list[dict[str, str]]]:
        """List active forward and reverse port tunnels."""
        if guard:
            guard()
        fwd_code, fwd_out, _ = await self._exec_cmd(["-s", serial, "forward", "--list"], timeout=4.0)
        if guard:
            guard()
        rev_code, rev_out, _ = await self._exec_cmd(["-s", serial, "reverse", "--list"], timeout=4.0)
        if guard:
            guard()
        forwards = []
        for line in fwd_out.decode("utf-8", errors="replace").splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[0] == serial:
                forwards.append({"serial": parts[0], "local": parts[1], "remote": parts[2], "type": "forward"})
        reverse = []
        for line in rev_out.decode("utf-8", errors="replace").splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[0] == serial:
                reverse.append({"serial": parts[0], "local": parts[1], "remote": parts[2], "type": "reverse"})
        return {
            "status": "success",
            "serial": serial,
            "forwards": forwards + reverse,
            "forward_only": forwards,
            "reverse_only": reverse,
        }

    async def create_forward(self, serial: str, local: str, remote: str, reverse: bool = False, guard: Optional[callable] = None) -> dict[str, Any]:
        """Create a port forward or reverse port tunnel."""
        if guard:
            guard()
        cmd = ["-s", serial, "reverse" if reverse else "forward", local, remote]
        code, out, err = await self._exec_cmd(cmd, timeout=5.0)
        if guard:
            guard()
        return {
            "status": "success" if code == 0 else "error",
            "type": "reverse" if reverse else "forward",
            "serial": serial,
            "local": local,
            "remote": remote,
            "code": code,
            "output": out.decode("utf-8", errors="replace").strip(),
            "error": err.decode("utf-8", errors="replace").strip(),
        }

    async def remove_forward(self, serial: str, local: str, reverse: bool = False, guard: Optional[callable] = None) -> dict[str, Any]:
        """Remove a specific forward or reverse tunnel."""
        if guard:
            guard()
        cmd = ["-s", serial, "reverse" if reverse else "forward", "--remove", local]
        code, out, err = await self._exec_cmd(cmd, timeout=5.0)
        if guard:
            guard()
        return {
            "status": "success" if code == 0 else "error",
            "serial": serial,
            "local": local,
            "reverse": reverse,
            "output": out.decode("utf-8", errors="replace").strip(),
        }

    async def remove_all_forwards(self, serial: str, reverse: bool = False, guard: Optional[callable] = None) -> dict[str, Any]:
        """Remove all forwards or reverse tunnels."""
        if guard:
            guard()
        cmd = ["-s", serial, "reverse" if reverse else "forward", "--remove-all"]
        code, out, err = await self._exec_cmd(cmd, timeout=5.0)
        if guard:
            guard()
        return {
            "status": "success" if code == 0 else "error",
            "serial": serial,
            "reverse": reverse,
            "all": True,
            "output": out.decode("utf-8", errors="replace").strip(),
        }

    async def dispatch_custom_intent(
        self,
        serial: str,
        target_type: str,
        component: Optional[str] = None,
        action: Optional[str] = None,
        data_uri: Optional[str] = None,
        mime_type: Optional[str] = None,
        categories: Optional[list[str]] = None,
        flags: Optional[list[str]] = None,
        extras: Optional[list[dict[str, str]]] = None,
        projection: Optional[str] = None,
        where: Optional[str] = None,
        guard: Optional[callable] = None,
    ) -> dict[str, Any]:
        """Craft and dispatch arbitrary intents or query content providers via ADB."""
        if guard:
            guard()

        if target_type == "content_query":
            uri = data_uri or component or ""
            cmd = ["-s", serial, "shell", "content", "query", "--uri", uri]
            if projection:
                cmd.extend(["--projection", projection])
            if where:
                cmd.extend(["--where", where])
        elif target_type == "content_delete":
            uri = data_uri or component or ""
            cmd = ["-s", serial, "shell", "content", "delete", "--uri", uri]
            if where:
                cmd.extend(["--where", where])
        elif target_type in ("activity", "broadcast", "service"):
            subcmd = "start" if target_type == "activity" else ("broadcast" if target_type == "broadcast" else "start-service")
            cmd = ["-s", serial, "shell", "am", subcmd]
            if component:
                cmd.extend(["-n", component])
            if action:
                cmd.extend(["-a", action])
            if data_uri:
                cmd.extend(["-d", data_uri])
            if mime_type:
                cmd.extend(["-t", mime_type])
            if categories:
                for cat in categories:
                    if cat:
                        cmd.extend(["-c", cat])
            if flags:
                for flg in flags:
                    if flg:
                        cmd.extend(["-f", flg])
            if extras:
                for extra in extras:
                    etype = extra.get("type", "string")
                    k = extra.get("key", "")
                    v = extra.get("value", "")
                    if not k:
                        continue
                    if etype in ("bool", "boolean"):
                        cmd.extend(["--ez", k, str(v).lower()])
                    elif etype in ("int", "integer"):
                        cmd.extend(["--ei", k, str(v)])
                    elif etype == "long":
                        cmd.extend(["--el", k, str(v)])
                    elif etype == "float":
                        cmd.extend(["--ef", k, str(v)])
                    else:
                        cmd.extend(["--es", k, str(v)])
        else:
            raise ValueError(f"Unknown target type: {target_type}")

        code, out, err = await self._exec_cmd(cmd, timeout=8.0)
        if guard:
            guard()
        out_text = out.decode("utf-8", errors="replace").strip()
        err_text = err.decode("utf-8", errors="replace").strip()
        crashed = "Exception" in out_text or "Error" in out_text or "CRASH" in out_text
        return {
            "status": "success" if code == 0 else "error",
            "code": code,
            "output": out_text or err_text,
            "raw_stdout": out_text,
            "raw_stderr": err_text,
            "crashed": crashed,
            "command": " ".join(cmd),
        }


