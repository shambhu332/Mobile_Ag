"""Live logcat streaming module for MobileAg dynamic analysis.

Streams Android logcat output as an async generator with configurable
rate limiting, filtering, and hard caps to prevent runaway I/O.

Inspired by the Loupe Android console (github.com/capt-meelo/loupe).
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import time
from typing import AsyncIterator, Callable, Optional
from mobileag.security.privacy import redact

logger = logging.getLogger(__name__)

# Hard cap on streamed lines per session to prevent runaway memory usage.
MAX_STREAM_LINES: int = 10_000

# Maximum lines per second delivered to the consumer (ergonomic rate limit).
MAX_LINES_PER_SECOND: int = 200

# Threadtime format: MM-DD HH:MM:SS.mmm PID TID LEVEL TAG  : message
_THREADTIME_RE = re.compile(
    r"^(?P<date>\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<pid>\d+)\s+"
    r"(?P<tid>\d+)\s+"
    r"(?P<level>[VDIWEFS])\s+"
    r"(?P<tag>[^:]+?)\s*:\s+"
    r"(?P<message>.*)$"
)

# Valid log levels ordered by verbosity (V → F).
_LOG_LEVELS = {"V", "D", "I", "W", "E", "F", "S"}
_LEVEL_ORDER = {lvl: idx for idx, lvl in enumerate("VDIWEFS")}


class LogcatStreamer:
    """Stream Android logcat output from a device as parsed dicts.

    Uses ``adb -s <serial> logcat -v threadtime`` under the hood and
    exposes each parsed log record through an async generator.  A
    configurable rate-limit (default 200 lines/sec) and a hard cap of
    :data:`MAX_STREAM_LINES` prevent runaway memory and I/O pressure.

    Usage::

        streamer = LogcatStreamer()
        async for record in streamer.stream("emulator-5554",
                                            package_filter="com.example.app",
                                            level_filter="W"):
            print(record)

    Parameters
    ----------
    adb_path:
        Explicit path to the ``adb`` binary.  When *None* (default)
        ``shutil.which("adb")`` is tried and ``/usr/bin/adb`` is used
        as a final fallback.
    """

    def __init__(self, adb_path: Optional[str] = None) -> None:
        self.adb_bin: str = (
            adb_path
            or shutil.which("adb")
            or "/usr/bin/adb"
        )

    # ------------------------------------------------------------------
    # Public streaming interface
    # ------------------------------------------------------------------

    async def stream(
        self,
        serial: str,
        *,
        package_filter: Optional[str] = None,
        level_filter: Optional[str] = None,
        tag_filter: Optional[str] = None,
        max_duration: float = 300.0,
        guard: Optional[Callable[[], bool]] = None,
    ) -> AsyncIterator[dict]:
        """Yield parsed logcat records from *serial* as an async generator.

        Each yielded item is a :class:`dict` with the following keys:

        * ``"timestamp"``  – ``"MM-DD HH:MM:SS.mmm"`` string
        * ``"pid"``        – integer process ID or *None* if unparseable
        * ``"tid"``        – integer thread ID or *None* if unparseable
        * ``"level"``      – single-character log level (``V/D/I/W/E/F``)
        * ``"tag"``        – tag string
        * ``"message"``    – log message body
        * ``"line_no"``    – 1-based ordinal within this streaming session

        Parameters
        ----------
        serial:
            ADB device serial (e.g. ``"emulator-5554"``).
        package_filter:
            Optional substring matched against the log *message* and
            *tag*.  **Not a security boundary** – purely ergonomic.
        level_filter:
            Minimum log level to include.  One of ``V D I W E F``.
            Records below this level are silently dropped.
        tag_filter:
            Exact tag string to include (case-insensitive substring
            match).
        max_duration:
            Maximum number of seconds to stream before the generator
            closes automatically.  Default 300 s.
        guard:
            Optional synchronous callable.  When provided it is called
            before the subprocess starts; if it returns ``False`` a
            :class:`PermissionError` is raised and streaming is denied.

        Yields
        ------
        dict
            Parsed logcat record (see above).

        Raises
        ------
        PermissionError
            If *guard* returns ``False``.
        RuntimeError
            If the ``adb`` binary cannot be found.
        asyncio.TimeoutError
            If the overall *max_duration* is exceeded.
        """
        # Guard check (synchronous, like ADBManager._check_mutation_guard)
        if guard is not None:
            if not callable(guard):
                raise PermissionError("LogcatStreamer.stream requires a callable guard")
            if guard() is False:
                raise PermissionError("LogcatStreamer stream scope is unavailable or revoked")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", serial):
            raise ValueError("Invalid ADB serial")
        if package_filter and not re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+", package_filter):
            raise ValueError("Invalid Android package name")
        if not 1 <= max_duration <= 300:
            raise ValueError("Logcat stream duration must be between 1 and 300 seconds")

        if not shutil.which(self.adb_bin) and self.adb_bin == "adb":
            # Try hard-coded fallback before giving up.
            import os
            if not os.path.isfile("/usr/bin/adb"):
                raise RuntimeError(
                    "adb binary not found. Install Android SDK platform-tools."
                )
            self.adb_bin = "/usr/bin/adb"

        # Validate level_filter early.
        min_level_idx: int = 0
        if level_filter:
            level_filter = level_filter.upper()
            if level_filter not in _LOG_LEVELS:
                raise ValueError(
                    f"Invalid level_filter {level_filter!r}. "
                    f"Must be one of: {sorted(_LOG_LEVELS)}"
                )
            min_level_idx = _LEVEL_ORDER.get(level_filter, 0)

        # Do not dump historical device logs into a new session. Even with PID
        # attribution, buffered entries can predate the observed process.
        cmd = [self.adb_bin, "-s", serial, "logcat", "-T", "1", "-v", "threadtime"]
        logger.debug("Starting logcat stream: %s", " ".join(cmd))

        proc: Optional[asyncio.subprocess.Process] = None
        line_no: int = 0
        target_pids: set[int] = set()
        # Sliding window for rate limiting: (timestamp, count) per second.
        window_start: float = time.monotonic()
        window_count: int = 0

        async def _run_stream() -> AsyncIterator[dict]:
            nonlocal proc, line_no, window_start, window_count

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )

            try:
                if package_filter:
                    pid_proc = await asyncio.create_subprocess_exec(
                        self.adb_bin, "-s", serial, "shell", "pidof", package_filter,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                    )
                    pid_out, _ = await asyncio.wait_for(pid_proc.communicate(), timeout=3.0)
                    if guard is not None and guard() is False:
                        raise PermissionError("Logcat stream scope was revoked")
                    target_pids.update(int(x) for x in pid_out.decode("ascii", errors="ignore").split()
                                       if x.isdecimal() and 0 < int(x) < 2**31)
                assert proc.stdout is not None  # always set with PIPE
                while line_no < MAX_STREAM_LINES:
                    try:
                        # Wake periodically even on an idle device so session
                        # rotation/scope revocation tears down adb promptly.
                        raw = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
                    except asyncio.TimeoutError:
                        if guard is not None and guard() is False:
                            raise PermissionError("Logcat stream scope was revoked")
                        continue
                    if not raw:
                        # Process ended.
                        break

                    text = raw.decode("utf-8", errors="replace").rstrip()
                    record = _parse_threadtime(text, line_no + 1)
                    if record is None:
                        continue

                    if guard is not None and guard() is False:
                        raise PermissionError("Logcat stream scope was revoked")
                    if package_filter and record["tag"] == "ActivityManager":
                        started = re.search(rf"\bStart proc (\d+):{re.escape(package_filter)}(?:/|:)", record["message"])
                        if started:
                            target_pids.add(int(started.group(1)))
                    if package_filter and record["pid"] not in target_pids:
                        continue

                    # ── Level filter ──────────────────────────────────
                    rec_level_idx = _LEVEL_ORDER.get(record["level"], 0)
                    if rec_level_idx < min_level_idx:
                        continue

                    # ── Tag filter ────────────────────────────────────
                    if tag_filter and tag_filter.lower() not in record["tag"].lower():
                        continue

                    # Package filtering is based on resolved process PIDs, not
                    # user-controlled tag/message substrings. Raw secrets are
                    # redacted before the record crosses the API boundary.
                    record["message"] = redact(record["message"])

                    # ── Rate limit (sliding 1-second window) ──────────
                    now = time.monotonic()
                    if now - window_start >= 1.0:
                        window_start = now
                        window_count = 0
                    window_count += 1
                    if window_count > MAX_LINES_PER_SECOND:
                        # Sleep for the remainder of the current window.
                        sleep_dur = 1.0 - (now - window_start)
                        if sleep_dur > 0:
                            await asyncio.sleep(sleep_dur)
                        window_start = time.monotonic()
                        window_count = 1

                    line_no += 1
                    yield record

            except asyncio.TimeoutError:
                logger.warning(
                    "Logcat stream on %s timed out after %.1f s (line %d).",
                    serial, max_duration, line_no,
                )
                return
            except asyncio.CancelledError:
                raise
            finally:
                await _cleanup(proc)

        # Wrap the inner generator in an overall duration guard.
        try:
            async with asyncio.timeout(max_duration):
                async for record in _run_stream():
                    yield record
        except asyncio.TimeoutError:
            logger.warning(
                "Logcat stream on %s exceeded max_duration of %.1f s.",
                serial, max_duration,
            )
        except GeneratorExit:
            pass
        finally:
            if proc is not None:
                await _cleanup(proc)

        if line_no >= MAX_STREAM_LINES:
            logger.info(
                "Logcat stream on %s reached MAX_STREAM_LINES=%d and stopped.",
                serial, MAX_STREAM_LINES,
            )


# ---------------------------------------------------------------------------
# Helpers (module-private)
# ---------------------------------------------------------------------------

def _parse_threadtime(line: str, line_no: int) -> Optional[dict]:
    """Parse a single logcat threadtime line into a record dict.

    Returns *None* for header lines or lines that do not match the
    expected format.
    """
    m = _THREADTIME_RE.match(line)
    if not m:
        return None

    try:
        pid = int(m.group("pid"))
    except (ValueError, TypeError):
        pid = None

    try:
        tid = int(m.group("tid"))
    except (ValueError, TypeError):
        tid = None

    return {
        "timestamp": f"{m.group('date')} {m.group('time')}",
        "pid": pid,
        "tid": tid,
        "level": m.group("level"),
        "tag": m.group("tag").strip(),
        "message": m.group("message"),
        "line_no": line_no,
    }


async def _cleanup(proc: Optional[asyncio.subprocess.Process]) -> None:
    """Terminate and reap a logcat subprocess, suppressing all errors."""
    if proc is None:
        return
    if proc.returncode is None:
        try:
            proc.kill()
            await asyncio.wait_for(proc.wait(), timeout=3.0)
        except Exception:
            pass
