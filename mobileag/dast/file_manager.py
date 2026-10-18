"""Device file-system manager for MobileAg dynamic testing.

Provides :class:`DeviceFileManager` for bounded, scoped directory and package
inventory from a connected Android device over ADB.

Security constraints enforced by this module
---------------------------------------------
* Every action requires a synchronous *guard* callable (same contract as
  :class:`~mobileag.dast.adb_manager.ADBManager`).
* All remote path inputs are validated: no ``..`` segments, no null bytes,
  and absolute paths must start with ``/``.
* Directory listings are capped at 500 entries.
* Package listings are capped at 500 entries.
* Package names for APK pull are validated against the standard Android
  reverse-domain regex.
* ``asyncio.wait_for`` wraps every subprocess call per GEMINI.md rules.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import shutil
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DIR_ENTRY_LIMIT: int = 500
_PKG_LIMIT: int = 500
_DIR_TIMEOUT: float = 5.0
_INFO_TIMEOUT: float = 10.0
_PKG_TIMEOUT: float = 15.0
_PULL_TIMEOUT: float = 60.0

_PKG_RE = re.compile(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+")
_SERIAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")

# Regex for a single ls -la output line (BusyBox / toybox / GNU coreutils)
# Example: -rw-r--r-- 1 root root 4096 2024-01-01 12:00 filename
_LS_LINE_RE = re.compile(
    r"^(?P<perms>[dlrwxstST\-]{10})\s+"   # permissions
    r"\d+\s+"                              # hard-link count
    r"\S+\s+"                              # owner
    r"\S+\s+"                              # group
    r"(?P<size>\d+)\s+"                    # size in bytes
    r"(?P<date>\S+(?:\s+\S+)?)\s+"        # date (may be "2024-01-01 12:00")
    r"(?P<name>.+)$"                       # filename (rest of line)
)


# ---------------------------------------------------------------------------
# Guard helper
# ---------------------------------------------------------------------------

def _check_guard(guard: Any) -> None:
    """Require a synchronous, current authorization check before device action.

    Parameters
    ----------
    guard:
        A callable returning a truthy value when the current request is
        within scope, or ``False`` / raises when it is not.

    Raises
    ------
    PermissionError
        When *guard* is missing, returns an awaitable, or returns ``False``.
    """
    if not callable(guard):
        raise PermissionError("DeviceFileManager action requires an explicit scope guard")
    result = guard()
    if inspect.isawaitable(result):
        close = getattr(result, "close", None)
        if callable(close):
            close()
        raise PermissionError("DeviceFileManager scope guard must be synchronous")
    if result is False:
        raise PermissionError("DeviceFileManager scope is unavailable or revoked")


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------

def _validate_path(path: str, *, must_be_absolute: bool = False) -> None:
    """Raise :class:`ValueError` for unsafe remote paths.

    Parameters
    ----------
    path:
        The remote Android path to validate.
    must_be_absolute:
        When ``True``, also requires the path to start with ``/``.

    Raises
    ------
    ValueError
        If the path contains ``..`` segments or null bytes, or is not
        absolute when *must_be_absolute* is ``True``.
    """
    if "\x00" in path:
        raise ValueError("Path must not contain null bytes")
    parts = path.replace("\\", "/").split("/")
    if ".." in parts:
        raise ValueError("Path traversal ('..') is not permitted")
    if must_be_absolute and not path.startswith("/"):
        raise ValueError("Remote path must be absolute (start with '/')")


def _validate_serial(serial: str) -> None:
    if not _SERIAL_RE.fullmatch(serial):
        raise ValueError("Invalid ADB serial")


# ---------------------------------------------------------------------------
# DeviceFileManager
# ---------------------------------------------------------------------------

class DeviceFileManager:
    """Browse package-scoped directories and inspect device inventories.

    Parameters
    ----------
    adb_path:
        Explicit path to the ``adb`` binary.  When *None*, resolved via
        ``shutil.which`` with a ``/usr/bin/adb`` fallback per GEMINI.md.

    Examples
    --------
    ::

        fm = DeviceFileManager()
        entries = await fm.list_directory("emulator-5554", "/sdcard", guard=g)
    """

    def __init__(self, adb_path: str | None = None) -> None:
        self._adb_bin: str = (
            adb_path
            or shutil.which("adb")
            or "/usr/bin/adb"
        )

    # ------------------------------------------------------------------
    # Internal ADB helper
    # ------------------------------------------------------------------

    async def _run(
        self,
        args: list[str],
        timeout: float,
        output_limit: int | None = None,
    ) -> tuple[int, bytes, bytes]:
        """Execute an ADB command with timeout and optional output cap.

        Parameters
        ----------
        args:
            Arguments appended to the ``adb`` binary path.
        timeout:
            Seconds before the subprocess is killed and ``-1`` is returned.
        output_limit:
            When set, stdout is read in streaming fashion and truncated at
            this many bytes.

        Returns
        -------
        tuple[int, bytes, bytes]
            ``(returncode, stdout, stderr)``
        """
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                self._adb_bin, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            if output_limit is None:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            else:
                async def _bounded_read(stream: asyncio.StreamReader) -> bytes:
                    data = bytearray()
                    while chunk := await stream.read(16_384):
                        remaining = output_limit - len(data)
                        data.extend(chunk[:remaining])
                        if len(data) >= output_limit:
                            break
                    return bytes(data)

                async def _finish() -> tuple[bytes, bytes]:
                    assert proc is not None
                    assert proc.stdout is not None
                    assert proc.stderr is not None
                    out, err = await asyncio.gather(
                        _bounded_read(proc.stdout),
                        _bounded_read(proc.stderr),
                    )
                    await proc.wait()
                    return out, err

                stdout, stderr = await asyncio.wait_for(_finish(), timeout=timeout)

            return proc.returncode or 0, stdout, stderr

        except asyncio.TimeoutError:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            logger.warning("ADB command timed out after %.1fs: %s", timeout, args)
            return -1, b"", b"[ADB command timed out]"
        except Exception as exc:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            logger.exception("ADB command error: %s", exc)
            return -1, b"", str(exc).encode()

    # ------------------------------------------------------------------
    # list_directory
    # ------------------------------------------------------------------

    async def list_directory(
        self,
        serial: str,
        path: str,
        guard: Any,
    ) -> dict[str, Any]:
        """List files and directories at *path* on the device.

        Parameters
        ----------
        serial:
            ADB device serial number.
        path:
            Absolute remote path to list.
        guard:
            Synchronous scope-guard callable.

        Returns
        -------
        dict
            ``{"path": str, "entries": [{"name": str, "type": str,
            "size": int|None, "permissions": str, "modified": str}]}``

            *type* is one of ``"file"``, ``"dir"``, or ``"symlink"``.
            Up to 500 entries are returned.

        Raises
        ------
        PermissionError
            If *guard* denies the action.
        ValueError
            If *path* is unsafe.
        """
        _check_guard(guard)
        _validate_serial(serial)
        _validate_path(path, must_be_absolute=True)

        code, stdout, stderr = await self._run(
            ["-s", serial, "shell", f"ls -la {shlex_quote(path)}"],
            timeout=_DIR_TIMEOUT,
            output_limit=256 * 1024,
        )
        _check_guard(guard)
        _validate_serial(serial)

        entries: list[dict[str, Any]] = []
        raw = stdout.decode("utf-8", errors="replace")

        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("total "):
                continue
            entry = _parse_ls_line(line)
            if entry is None:
                continue
            entries.append(entry)
            if len(entries) >= _DIR_ENTRY_LIMIT:
                logger.debug("list_directory entry limit reached for path: %s", path)
                break

        return {"path": path, "entries": entries}

    # ------------------------------------------------------------------
    # get_device_info
    # ------------------------------------------------------------------

    async def get_device_info(self, serial: str, guard: Any) -> dict[str, str]:
        """Return a curated set of device properties from ``getprop``.

        Parameters
        ----------
        serial:
            ADB device serial number.
        guard:
            Synchronous scope-guard callable.

        Returns
        -------
        dict
            Keys: ``model``, ``manufacturer``, ``android_version``,
            ``sdk_int``, ``build_id``, ``fingerprint``, ``cpu_abi``.
            Missing properties default to ``"Unknown"``.
        """
        _check_guard(guard)
        _validate_serial(serial)

        code, stdout, _ = await self._run(
            ["-s", serial, "shell", "getprop"],
            timeout=_INFO_TIMEOUT,
            output_limit=256 * 1024,
        )
        _check_guard(guard)
        _validate_serial(serial)

        props: dict[str, str] = {}
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            m = re.match(r"^\[([^\]]+)\]:\s*\[([^\]]*)\]$", line.strip())
            if m:
                props[m.group(1)] = m.group(2)

        def _get(key: str) -> str:
            return props.get(key, "Unknown") or "Unknown"

        return {
            "model": _get("ro.product.model"),
            "manufacturer": _get("ro.product.manufacturer"),
            "android_version": _get("ro.build.version.release"),
            "sdk_int": _get("ro.build.version.sdk"),
            "build_id": _get("ro.build.id"),
            "fingerprint": _get("ro.build.fingerprint"),
            "cpu_abi": _get("ro.product.cpu.abi"),
        }

    # ------------------------------------------------------------------
    # list_packages
    # ------------------------------------------------------------------

    async def list_packages(
        self,
        serial: str,
        guard: Any,
        include_system: bool = False,
    ) -> list[dict[str, str]]:
        """Enumerate installed packages using ``pm list packages -f``.

        Parameters
        ----------
        serial:
            ADB device serial number.
        guard:
            Synchronous scope-guard callable.
        include_system:
            When ``False`` (default), only third-party packages are listed
            (``pm list packages -f -3``).

        Returns
        -------
        list[dict]
            Each element has keys ``"package"`` (str) and ``"apk_path"`` (str).
            At most 500 packages are returned.
        """
        _check_guard(guard)

        pm_args = ["pm", "list", "packages", "-f"]
        if not include_system:
            pm_args.append("-3")

        code, stdout, _ = await self._run(
            ["-s", serial, "shell"] + pm_args,
            timeout=_PKG_TIMEOUT,
            output_limit=512 * 1024,
        )
        _check_guard(guard)

        packages: list[dict[str, str]] = []
        # Output format: package:<apk_path>=<package_name>
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("package:"):
                continue
            rest = line[len("package:"):]
            eq_idx = rest.rfind("=")
            if eq_idx == -1:
                continue
            apk_path = rest[:eq_idx]
            pkg_name = rest[eq_idx + 1:]
            if not apk_path or not pkg_name:
                continue
            packages.append({"package": pkg_name, "apk_path": apk_path})
            if len(packages) >= _PKG_LIMIT:
                logger.debug("list_packages limit reached for device %s", serial)
                break

        return packages

    # ------------------------------------------------------------------
    # pull_apk
    # ------------------------------------------------------------------

    async def pull_apk(
        self,
        serial: str,
        package_name: str,
        dest_dir: str | Path,
        guard: Any,
    ) -> dict[str, str]:
        """Pull an installed APK to a local directory.

        The APK path is resolved via ``pm path`` before pulling so that no
        user-supplied path reaches the device directly.

        Parameters
        ----------
        serial:
            ADB device serial number.
        package_name:
            Android package name (e.g. ``com.example.app``).  Validated
            against the standard reverse-domain regex.
        dest_dir:
            Local directory where the APK will be saved.
        guard:
            Synchronous scope-guard callable.  Checked before **and** after
            the pull operation.

        Returns
        -------
        dict
            ``{"status": str, "local_path": str, "package": str}``

        Raises
        ------
        PermissionError
            If *guard* denies the action.
        ValueError
            If *package_name* is invalid.
        """
        _check_guard(guard)

        if not _PKG_RE.fullmatch(package_name):
            raise ValueError(f"Invalid Android package name: {package_name!r}")

        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)

        # Resolve APK path on device.
        code, stdout, _ = await self._run(
            ["-s", serial, "shell", "pm", "path", package_name],
            timeout=10.0,
        )
        _check_guard(guard)

        raw_path_line = stdout.decode("utf-8", errors="replace").strip()
        # Output: "package:/data/app/com.example.app-1/base.apk"
        if not raw_path_line.startswith("package:"):
            return {
                "status": "error",
                "local_path": "",
                "package": package_name,
            }

        apk_path = raw_path_line[len("package:"):].strip()
        _validate_path(apk_path, must_be_absolute=True)

        local_path = str(dest / f"{package_name}.apk")

        code, stdout, stderr = await self._run(
            ["-s", serial, "pull", apk_path, local_path],
            timeout=_PULL_TIMEOUT,
        )
        _check_guard(guard)

        if code == 0:
            logger.info("APK pulled: %s -> %s", package_name, local_path)
            return {"status": "success", "local_path": local_path, "package": package_name}

        err_msg = stderr.decode("utf-8", errors="replace").strip()
        logger.warning("pull_apk failed for %s: %s", package_name, err_msg)
        return {"status": "error", "local_path": "", "package": package_name}


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def shlex_quote(s: str) -> str:
    """Return a shell-escaped version of *s* suitable for ``adb shell``.

    Uses single-quoting to avoid injection.  Embedded single-quotes are
    escaped by closing the quote, inserting a literal ``'``, then reopening.
    """
    return "'" + s.replace("'", "'\\''") + "'"


def _parse_ls_line(line: str) -> dict[str, Any] | None:
    """Parse a single line of ``ls -la`` output into an entry dict.

    Parameters
    ----------
    line:
        One non-empty, non-header line from ``ls -la`` stdout.

    Returns
    -------
    dict or None
        ``{"name": str, "type": str, "size": int|None,
        "permissions": str, "modified": str}``
        or ``None`` if the line cannot be parsed.
    """
    m = _LS_LINE_RE.match(line)
    if not m:
        return None

    perms = m.group("perms")
    size_str = m.group("size")
    date_str = m.group("date")
    name = m.group("name").strip()

    # Determine entry type from first permission character.
    first = perms[0] if perms else "-"
    if first == "d":
        entry_type = "dir"
    elif first == "l":
        entry_type = "symlink"
        # Strip symlink target: "name -> target"
        if " -> " in name:
            name = name.split(" -> ", 1)[0].strip()
    else:
        entry_type = "file"

    try:
        size: int | None = int(size_str)
    except (ValueError, TypeError):
        size = None

    return {
        "name": name,
        "type": entry_type,
        "size": size,
        "permissions": perms,
        "modified": date_str,
    }
