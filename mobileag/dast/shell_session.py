"""Scoped interactive ADB shell session for MobileAg dynamic testing.

Provides :class:`ShellSession` for a long-lived ``adb shell`` subprocess
(interactive mode) and a lightweight :meth:`ShellSession.run_one` helper
that spawns a fresh subprocess per invocation.

Security constraints enforced by this module
---------------------------------------------
* Every action requires a synchronous *guard* callable (same
  contract as :class:`~mobileag.dast.adb_manager.ADBManager`).
* Only an exact, read-only diagnostic command allowlist is accepted.
* Command length is capped at 4 096 characters.
* Output per command is capped at 64 KB.
* Sessions expire after a configurable lifetime (default 30 minutes).
* A maximum of 500 commands may be issued per session.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import shlex
import shutil
import time
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CMD_MAX_LEN: int = 4_096
_OUTPUT_MAX_BYTES: int = 64 * 1024          # 64 KB per command
_SESSION_LIFETIME_DEFAULT: float = 30 * 60  # 30 minutes in seconds
_SESSION_CMD_LIMIT: int = 500
_RUN_ONE_OUTPUT_MAX: int = 65_536           # 64 KB for run_one
_SENTINEL: str = "__MOBILEAG_SENTINEL_EOF__"

# ---------------------------------------------------------------------------
# Guard helper (mirrors ADBManager._check_mutation_guard)
# ---------------------------------------------------------------------------

def _check_guard(guard: Any) -> None:
    """Require a synchronous, current authorization check before shell action.

    Parameters
    ----------
    guard:
        A callable that returns a truthy value when the current request is
        within scope, or ``False`` / raises when it is not.

    Raises
    ------
    PermissionError
        When *guard* is missing, returns an awaitable, or returns ``False``.
    """
    if not callable(guard):
        raise PermissionError("ShellSession action requires an explicit scope guard")
    result = guard()
    if inspect.isawaitable(result):
        close = getattr(result, "close", None)
        if callable(close):
            close()
        raise PermissionError("ShellSession scope guard must be synchronous")
    if result is False:
        raise PermissionError("ShellSession scope is unavailable or revoked")


def _validate_command(cmd: str) -> None:
    """Raise :class:`ValueError` if *cmd* violates security constraints.

    Checks performed
    ----------------
    * Stripped length ≤ 4 096 characters.
    * Is in the exact read-only diagnostic allowlist.

    Parameters
    ----------
    cmd:
        The shell command string to validate.
    """
    stripped = cmd.strip()
    if len(stripped) > _CMD_MAX_LEN:
        raise ValueError(
            f"Command exceeds maximum length of {_CMD_MAX_LEN} characters"
        )
    if not stripped or any(ch in stripped for ch in "\r\n\x00"):
        raise ValueError("Command must be a single non-empty line")
    try:
        parts = shlex.split(stripped, posix=True)
    except ValueError as exc:
        raise ValueError("Command quoting is invalid") from exc
    # Exact read-only diagnostic grammar. A prefix deny-list is not safe for a
    # shell because pipes, substitutions, redirects and alternate spellings can
    # bypass it. No shell metacharacters or arbitrary paths are accepted.
    pkg = r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+"
    prop = r"[A-Za-z0-9_.-]{1,128}"
    safe = (
        parts in (["id"], ["whoami"], ["pwd"], ["uptime"], ["df", "-h"],
                  ["cat", "/proc/meminfo"], ["dumpsys", "battery"], ["ps", "-A"])
        or parts in (["pm", "list", "packages"], ["pm", "list", "packages", "-3"])
        or (len(parts) == 2 and parts[0] == "getprop" and re.fullmatch(prop, parts[1]))
        or (len(parts) == 3 and parts[0] == "dumpsys" and parts[1] in {"package", "meminfo"}
            and re.fullmatch(pkg, parts[2]))
        or (len(parts) == 3 and parts[:2] == ["settings", "list"]
            and parts[2] in {"system", "secure", "global"})
    )
    if not safe:
        raise ValueError("Command is not in the read-only diagnostic allowlist")


def _validate_serial(serial: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", serial):
        raise ValueError("Invalid ADB serial")


# ---------------------------------------------------------------------------
# ShellSession
# ---------------------------------------------------------------------------

class ShellSession:
    """Manages a persistent ``adb shell`` subprocess for interactive use.

    The session writes commands to the subprocess stdin and reads output
    until a sentinel string appears on stdout, providing a simple
    request/response model over an interactive PTY-less shell.

    Parameters
    ----------
    adb_path:
        Explicit path to the ``adb`` binary.  When *None*, resolved via
        ``shutil.which`` with a ``/usr/bin/adb`` fallback.
    lifetime_seconds:
        Maximum number of seconds this session may remain open before
        :meth:`send_command` raises :class:`RuntimeError`.  Defaults to
        1 800 s (30 minutes).

    Examples
    --------
    ::

        session = ShellSession()
        await session.start("emulator-5554", guard=lambda: True)
        output = await session.send_command("id", guard=lambda: True)
        await session.close()
    """

    def __init__(
        self,
        adb_path: str | None = None,
        lifetime_seconds: float = _SESSION_LIFETIME_DEFAULT,
    ) -> None:
        self._adb_bin: str = (
            adb_path
            or shutil.which("adb")
            or "/usr/bin/adb"
        )
        self._lifetime: float = max(1.0, lifetime_seconds)
        self._proc: asyncio.subprocess.Process | None = None
        self._serial: str = ""
        self._started_at: float = 0.0
        self._cmd_count: int = 0
        self._lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def start(self, serial: str, guard: Any) -> None:
        """Start a persistent ``adb -s <serial> shell`` subprocess.

        Parameters
        ----------
        serial:
            ADB serial number of the target device.
        guard:
            Synchronous scope-guard callable (see module docstring).

        Raises
        ------
        PermissionError
            If *guard* is missing or denies the action.
        RuntimeError
            If a session is already active.
        """
        _check_guard(guard)
        _validate_serial(serial)
        if self._proc is not None and self._proc.returncode is None:
            raise RuntimeError("A shell session is already active; call close() first")

        self._serial = serial
        self._proc = await asyncio.create_subprocess_exec(
            self._adb_bin, "-s", serial, "shell",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._started_at = time.monotonic()
        self._cmd_count = 0
        logger.info("ShellSession started for device %s (pid=%s)", serial, self._proc.pid)

    async def send_command(
        self,
        cmd: str,
        guard: Any,
        timeout: float = 10.0,
    ) -> str:
        """Send a single command and collect output until the sentinel appears.

        The sentinel ``echo`` is appended automatically so that the reader
        knows when output for this command ends.

        Parameters
        ----------
        cmd:
            Shell command to execute.  Must not exceed 4 096 characters and
            must not start with a blocked prefix.
        guard:
            Synchronous scope-guard callable.
        timeout:
            Seconds to wait for the sentinel before raising
            :class:`asyncio.TimeoutError`.

        Returns
        -------
        str
            Decoded output of the command (up to 64 KB, stripped).

        Raises
        ------
        PermissionError
            If *guard* denies the action.
        ValueError
            If the command violates security constraints.
        RuntimeError
            If the session is not alive, the lifetime has expired, or the
            command limit has been reached.
        asyncio.TimeoutError
            If the command does not complete within *timeout* seconds.
        """
        _check_guard(guard)
        _validate_command(cmd)

        if not self.is_alive:
            raise RuntimeError("Shell session is not active; call start() first")

        elapsed = time.monotonic() - self._started_at
        if elapsed > self._lifetime:
            await self.close()
            raise RuntimeError(
                f"Shell session lifetime of {self._lifetime:.0f}s exceeded; "
                "session has been closed"
            )

        if self._cmd_count >= _SESSION_CMD_LIMIT:
            await self.close()
            raise RuntimeError(
                f"Shell session command limit of {_SESSION_CMD_LIMIT} reached; "
                "session has been closed"
            )

        async with self._lock:
            return await asyncio.wait_for(
                self._do_send(cmd),
                timeout=timeout,
            )

    async def close(self) -> None:
        """Terminate the underlying subprocess and release resources."""
        if self._proc is None:
            return
        proc = self._proc
        self._proc = None
        if proc.returncode is None:
            try:
                proc.stdin.write(b"exit\n")
                await proc.stdin.drain()
            except Exception:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except (asyncio.TimeoutError, Exception):
                proc.kill()
                try:
                    await proc.wait()
                except Exception:
                    pass
        logger.info(
            "ShellSession closed for device %s after %d commands",
            self._serial,
            self._cmd_count,
        )

    # ------------------------------------------------------------------
    # Non-interactive helper
    # ------------------------------------------------------------------

    async def run_one(
        self,
        serial: str,
        command: str,
        guard: Any,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        """Run a single command via a fresh ``adb -s <serial> shell`` subprocess.

        This method does **not** use the persistent session subprocess.  Each
        call spawns its own ``adb`` process, making it safe to use from any
        context without calling :meth:`start` first.

        Parameters
        ----------
        serial:
            ADB device serial number.
        command:
            Shell command to execute.  Same security constraints as
            :meth:`send_command` apply.
        guard:
            Synchronous scope-guard callable.
        timeout:
            Maximum seconds for the subprocess to complete (capped at 90 s
            per GEMINI.md rules).

        Returns
        -------
        dict
            ``{"output": str, "exit_code": int, "command": str, "serial": str}``

        Raises
        ------
        PermissionError
            If *guard* denies the action.
        ValueError
            If the command violates security constraints.
        """
        _check_guard(guard)
        _validate_serial(serial)
        _validate_command(command)

        safe_timeout = min(float(timeout), 90.0)
        adb_bin = shutil.which("adb") or "/usr/bin/adb"

        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                adb_bin, "-s", serial, "shell", command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            async def _collect() -> bytes:
                assert proc is not None
                buf = bytearray()
                assert proc.stdout is not None
                while chunk := await proc.stdout.read(16_384):
                    buf.extend(chunk)
                    if len(buf) > _RUN_ONE_OUTPUT_MAX:
                        logger.warning(
                            "run_one output limit (%d bytes) reached for command: %s",
                            _RUN_ONE_OUTPUT_MAX,
                            command[:80],
                        )
                        break
                await proc.wait()
                return bytes(buf[:_RUN_ONE_OUTPUT_MAX])

            raw = await asyncio.wait_for(_collect(), timeout=safe_timeout)
            _check_guard(guard)
            return {
                "output": raw.decode("utf-8", errors="replace").strip(),
                "exit_code": proc.returncode or 0,
                "command": command,
                "serial": serial,
            }

        except asyncio.TimeoutError:
            if proc and proc.returncode is None:
                proc.kill()
                try:
                    await proc.wait()
                except Exception:
                    pass
            logger.warning("run_one timed out after %.1fs: %s", safe_timeout, command[:80])
            return {
                "output": f"[TIMEOUT after {safe_timeout}s]",
                "exit_code": -1,
                "command": command,
                "serial": serial,
            }
        except Exception as exc:
            if proc and proc.returncode is None:
                proc.kill()
                try:
                    await proc.wait()
                except Exception:
                    pass
            logger.exception("run_one failed: %s", exc)
            return {
                "output": f"[ERROR: {exc}]",
                "exit_code": -1,
                "command": command,
                "serial": serial,
            }

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_alive(self) -> bool:
        """``True`` when the underlying subprocess is running."""
        return self._proc is not None and self._proc.returncode is None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _do_send(self, cmd: str) -> str:
        """Write *cmd* and read stdout until the sentinel line appears.

        This is the inner coroutine protected by the session lock and wrapped
        in :func:`asyncio.wait_for` by the caller.
        """
        assert self._proc is not None
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None

        sentinel_line = _SENTINEL + "\n"
        # Compose the full payload: run the command, then echo the sentinel.
        payload = f"{cmd}\necho {_SENTINEL}\n"
        self._proc.stdin.write(payload.encode("utf-8", errors="replace"))
        await self._proc.stdin.drain()
        self._cmd_count += 1

        buf = bytearray()
        while True:
            line_bytes = await self._proc.stdout.readline()
            if not line_bytes:
                # EOF — process has exited unexpectedly.
                break
            line = line_bytes.decode("utf-8", errors="replace")
            if line.rstrip("\r\n") == _SENTINEL:
                break
            buf.extend(line_bytes)
            if len(buf) > _OUTPUT_MAX_BYTES:
                logger.warning(
                    "ShellSession output limit (%d bytes) reached; truncating",
                    _OUTPUT_MAX_BYTES,
                )
                # Drain remaining output until sentinel without storing it.
                while True:
                    drain_line = await self._proc.stdout.readline()
                    if not drain_line:
                        break
                    if drain_line.decode("utf-8", errors="replace").rstrip("\r\n") == _SENTINEL:
                        break
                break

        return bytes(buf[:_OUTPUT_MAX_BYTES]).decode("utf-8", errors="replace").strip()
