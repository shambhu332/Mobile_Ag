"""Device performance metrics collection for MobileAg dynamic analysis.

Collects CPU, memory, battery, network, storage, and frame-timing
metrics from an Android device via ``adb shell`` commands.  All
sub-commands run in parallel using :func:`asyncio.gather` to minimise
wall-clock latency.

Inspired by the Loupe Android console (github.com/capt-meelo/loupe).
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import time
from typing import Any, AsyncIterator, Optional

logger = logging.getLogger(__name__)

# Per-command adb shell timeout in seconds.
_CMD_TIMEOUT: float = 3.0
_CMD_OUTPUT_MAX: int = 256 * 1024


class DeviceMetricsCollector:
    """Collect real-time performance metrics from an Android device.

    Each call to :meth:`collect_snapshot` fires all ``adb shell``
    sub-commands **in parallel** and returns a single dict with
    structured and raw sub-sections for CPU, memory, battery, network,
    storage, and frame timing.

    Usage::

        collector = DeviceMetricsCollector()
        snapshot = await collector.collect_snapshot("emulator-5554",
                                                    package_name="com.example")
        print(snapshot["cpu"]["total_percent"])

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
    # Public API
    # ------------------------------------------------------------------

    async def collect_snapshot(
        self,
        serial: str,
        package_name: Optional[str] = None,
        guard: Any = None,
    ) -> dict:
        """Collect a single performance snapshot from *serial*.

        All six metric sub-commands run concurrently.  Each sub-dict
        contains at minimum a ``"raw"`` key (the unparsed adb output)
        and additional parsed fields.

        Parameters
        ----------
        serial:
            ADB device serial (e.g. ``"emulator-5554"``).
        package_name:
            Optional Android package identifier.  When provided, CPU and
            memory metrics are scoped to that process, and frame-timing
            data is attempted via SurfaceFlinger.

        Returns
        -------
        dict
            Keys: ``cpu``, ``memory``, ``battery``, ``network``,
            ``storage``, ``fps``, ``timestamp`` (:class:`float`),
            ``serial`` (:class:`str`).
        """
        ts = time.time()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", serial):
            raise ValueError("Invalid ADB serial")
        if package_name is not None and not re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+", package_name):
            raise ValueError("Invalid Android package name")
        _check_guard(guard)

        (
            cpu_raw,
            mem_raw,
            bat_raw,
            net_raw,
            stor_raw,
            fps_raw,
        ) = await asyncio.gather(
            self._shell(serial, "dumpsys cpuinfo", guard),
            self._shell(serial, f"dumpsys meminfo {package_name}" if package_name else "cat /proc/meminfo", guard),
            self._shell(serial, "dumpsys battery", guard),
            self._shell(serial, "cat /proc/net/dev", guard),
            self._shell(serial, "df /data", guard),
            self._shell(serial, f"dumpsys SurfaceFlinger --latency \"{package_name}\"" if package_name
                        else "dumpsys SurfaceFlinger --latency", guard),
            return_exceptions=False,
        )

        return {
            "cpu": _parse_cpu(cpu_raw, package_name),
            "memory": _parse_memory(mem_raw, package_name),
            "battery": _parse_battery(bat_raw),
            "network": _parse_network(net_raw),
            "storage": _parse_storage(stor_raw),
            "fps": _parse_fps(fps_raw),
            "timestamp": ts,
            "serial": serial,
        }

    async def stream_metrics(
        self,
        serial: str,
        package_name: Optional[str] = None,
        interval: float = 2.0,
        max_samples: int = 150,
        guard: Any = None,
    ) -> AsyncIterator[dict]:
        """Yield performance snapshots at *interval* seconds for up to *max_samples* iterations.

        Parameters
        ----------
        serial:
            ADB device serial.
        package_name:
            Optional package filter forwarded to :meth:`collect_snapshot`.
        interval:
            Seconds to wait between consecutive snapshots.  Default 2.0.
        max_samples:
            Maximum number of snapshots to yield before stopping.
            Default 150 (≈ 5 minutes at 2 s interval).

        Yields
        ------
        dict
            Performance snapshot as returned by :meth:`collect_snapshot`.
        """
        for sample_idx in range(max_samples):
            _check_guard(guard)
            snapshot = await self.collect_snapshot(serial, package_name, guard)
            snapshot["sample_index"] = sample_idx
            yield snapshot
            if sample_idx < max_samples - 1:
                await asyncio.sleep(interval)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _shell(self, serial: str, command: str, guard: Any = None) -> str:
        """Run ``adb -s <serial> shell <command>`` and return stdout as a string.

        Times out after :data:`_CMD_TIMEOUT` seconds and returns an
        empty string on failure, ensuring a single slow command never
        blocks the whole :func:`asyncio.gather` call.
        """
        proc: Optional[asyncio.subprocess.Process] = None
        try:
            _check_guard(guard)
            proc = await asyncio.create_subprocess_exec(
                self.adb_bin, "-s", serial, "shell", command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            assert proc.stdout is not None
            async def _read_limited() -> bytes:
                data = bytearray()
                while chunk := await proc.stdout.read(16_384):
                    data.extend(chunk[:_CMD_OUTPUT_MAX - len(data)])
                    if len(data) >= _CMD_OUTPUT_MAX:
                        # Prevent a noisy/hostile device command from retaining
                        # unbounded output or blocking the reader indefinitely.
                        if proc.returncode is None:
                            proc.kill()
                        break
                return bytes(data)
            stdout = await asyncio.wait_for(_read_limited(), timeout=_CMD_TIMEOUT)
            if proc.returncode is None:
                await asyncio.wait_for(proc.wait(), timeout=_CMD_TIMEOUT)
            _check_guard(guard)
            return stdout.decode("utf-8", errors="replace")
        except PermissionError:
            if proc and proc.returncode is None:
                proc.kill()
                await proc.wait()
            raise
        except asyncio.TimeoutError:
            logger.warning(
                "adb shell command timed out on %s: %r", serial, command
            )
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return ""
        except Exception as exc:
            logger.debug("adb shell error on %s (%r): %s", serial, command, exc)
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
            return ""


def _check_guard(guard: Any) -> None:
    """Require an explicit current scope guard for device metrics."""
    if not callable(guard):
        raise PermissionError("Device metrics require an explicit scope guard")
    result = guard()
    if asyncio.iscoroutine(result):
        result.close()
        raise PermissionError("Device metrics scope guard must be synchronous")
    if result is False:
        raise PermissionError("Device metrics scope is unavailable or revoked")


# ---------------------------------------------------------------------------
# Parsers (module-private)
# ---------------------------------------------------------------------------

def _parse_cpu(raw: str, package_name: Optional[str] = None) -> dict:
    """Parse ``dumpsys cpuinfo`` output.

    Returns
    -------
    dict
        * ``raw``           – unparsed string
        * ``total_percent`` – total CPU % (float or None)
        * ``process_percent`` – per-process CPU % for *package_name* (float or None)
        * ``top_processes``  – list of ``{"name": str, "percent": float}`` for top 10
    """
    result: dict = {"raw": raw, "total_percent": None, "process_percent": None, "top_processes": []}
    if not raw:
        return result

    # Extract total CPU: "Total CPU usage from X to Y" line, or the summary line.
    total_m = re.search(r"(\d+(?:\.\d+)?)\s*%\s+(?:TOTAL|total)", raw, re.IGNORECASE)
    if total_m:
        try:
            result["total_percent"] = float(total_m.group(1))
        except ValueError:
            pass

    # Alternatively look for: "Load: X / Y / Z" style (older Android)
    if result["total_percent"] is None:
        load_m = re.search(r"Load:\s*([\d.]+)", raw)
        if load_m:
            try:
                result["total_percent"] = float(load_m.group(1))
            except ValueError:
                pass

    # Per-process: lines like "  5.2% 1234/com.example.app: ..."
    top: list[dict] = []
    for m in re.finditer(r"([\d.]+)%\s+\d+/([\w.:]+)", raw):
        try:
            pct = float(m.group(1))
            name = m.group(2)
            top.append({"name": name, "percent": pct})
            if package_name and package_name in name and result["process_percent"] is None:
                result["process_percent"] = pct
        except ValueError:
            continue
    result["top_processes"] = top[:10]
    return result


def _parse_memory(raw: str, package_name: Optional[str] = None) -> dict:
    """Parse ``dumpsys meminfo <pkg>`` or ``/proc/meminfo`` output.

    Returns
    -------
    dict
        * ``raw``              – unparsed string
        * ``total_kb``         – total RAM in kB (int or None)
        * ``available_kb``     – available RAM in kB (int or None)
        * ``pss_total_kb``     – PSS total for package in kB (int or None)
        * ``heap_size_kb``     – Java heap size in kB (int or None)
        * ``heap_alloc_kb``    – Java heap allocated in kB (int or None)
    """
    result: dict = {
        "raw": raw,
        "total_kb": None,
        "available_kb": None,
        "pss_total_kb": None,
        "heap_size_kb": None,
        "heap_alloc_kb": None,
    }
    if not raw:
        return result

    if package_name:
        # dumpsys meminfo output: "TOTAL PSS:   12345 kB"
        pss_m = re.search(r"TOTAL\s+PSS:\s*(\d+)\s*kB", raw, re.IGNORECASE)
        if pss_m:
            try:
                result["pss_total_kb"] = int(pss_m.group(1))
            except ValueError:
                pass
        # Heap: "Java Heap:   Heap Size  Heap Alloc  Heap Free"
        heap_m = re.search(r"Java Heap:\s+(\d+)\s+(\d+)", raw)
        if heap_m:
            try:
                result["heap_size_kb"] = int(heap_m.group(1))
                result["heap_alloc_kb"] = int(heap_m.group(2))
            except ValueError:
                pass
    else:
        # /proc/meminfo
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            key, val = parts[0].rstrip(":"), parts[1]
            try:
                if key == "MemTotal":
                    result["total_kb"] = int(val)
                elif key == "MemAvailable":
                    result["available_kb"] = int(val)
            except ValueError:
                pass

    return result


def _parse_battery(raw: str) -> dict:
    """Parse ``dumpsys battery`` output.

    Returns
    -------
    dict
        * ``raw``         – unparsed string
        * ``level``       – battery level 0-100 (int or None)
        * ``temperature`` – temperature in tenths of °C (int or None)
        * ``status``      – status string or None
        * ``plugged``     – plugged source string or None
        * ``voltage``     – voltage in mV (int or None)
    """
    result: dict = {
        "raw": raw,
        "level": None,
        "temperature": None,
        "status": None,
        "plugged": None,
        "voltage": None,
    }
    if not raw:
        return result

    _INT_FIELDS = {
        "level": "level",
        "temperature": "temperature",
        "voltage": "voltage",
    }
    _STR_FIELDS = {
        "status": "status",
        "plugged": "plugged",
    }
    # Status integer codes
    _STATUS_MAP = {
        "1": "unknown", "2": "charging", "3": "discharging",
        "4": "not_charging", "5": "full",
    }
    _PLUGGED_MAP = {
        "0": "unplugged", "1": "ac", "2": "usb", "4": "wireless",
    }

    for line in raw.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        for field, out_key in _INT_FIELDS.items():
            if k == field:
                try:
                    result[out_key] = int(v)
                except ValueError:
                    pass
        if k == "status":
            result["status"] = _STATUS_MAP.get(v, v)
        if k == "plugged":
            result["plugged"] = _PLUGGED_MAP.get(v, v)

    return result


def _parse_network(raw: str) -> dict:
    """Parse ``/proc/net/dev`` for wlan0/eth0 rx/tx bytes.

    Returns
    -------
    dict
        * ``raw``           – unparsed string
        * ``interfaces``    – list of ``{"name": str, "rx_bytes": int, "tx_bytes": int}``
        * ``wlan0_rx``      – rx bytes for wlan0 (int or None)
        * ``wlan0_tx``      – tx bytes for wlan0 (int or None)
        * ``eth0_rx``       – rx bytes for eth0 (int or None)
        * ``eth0_tx``       – tx bytes for eth0 (int or None)
    """
    result: dict = {
        "raw": raw,
        "interfaces": [],
        "wlan0_rx": None,
        "wlan0_tx": None,
        "eth0_rx": None,
        "eth0_tx": None,
    }
    if not raw:
        return result

    for line in raw.splitlines():
        # Format: "  iface: rx_bytes rx_packets ... tx_bytes ..."
        m = re.match(r"\s*(\S+):\s+([\d\s]+)", line)
        if not m:
            continue
        iface = m.group(1)
        fields = m.group(2).split()
        if len(fields) < 9:
            continue
        try:
            rx_bytes = int(fields[0])
            tx_bytes = int(fields[8])
        except (ValueError, IndexError):
            continue
        entry = {"name": iface, "rx_bytes": rx_bytes, "tx_bytes": tx_bytes}
        result["interfaces"].append(entry)
        if iface == "wlan0":
            result["wlan0_rx"] = rx_bytes
            result["wlan0_tx"] = tx_bytes
        elif iface == "eth0":
            result["eth0_rx"] = rx_bytes
            result["eth0_tx"] = tx_bytes

    return result


def _parse_storage(raw: str) -> dict:
    """Parse ``df /data`` output.

    Returns
    -------
    dict
        * ``raw``            – unparsed string
        * ``filesystem``     – filesystem path (str or None)
        * ``total_blocks``   – total 1K-blocks (int or None)
        * ``used_blocks``    – used 1K-blocks (int or None)
        * ``available_blocks`` – available 1K-blocks (int or None)
        * ``use_percent``    – usage percentage string (str or None)
    """
    result: dict = {
        "raw": raw,
        "filesystem": None,
        "total_blocks": None,
        "used_blocks": None,
        "available_blocks": None,
        "use_percent": None,
    }
    if not raw:
        return result

    for line in raw.splitlines():
        if line.startswith("Filesystem") or not line.strip():
            continue
        parts = line.split()
        # Standard df: Filesystem 1K-blocks Used Available Use% Mounted
        if len(parts) >= 5:
            try:
                result["filesystem"] = parts[0]
                result["total_blocks"] = int(parts[1])
                result["used_blocks"] = int(parts[2])
                result["available_blocks"] = int(parts[3])
                result["use_percent"] = parts[4]
            except (ValueError, IndexError):
                pass
            break

    return result


def _parse_fps(raw: str) -> dict:
    """Parse ``dumpsys SurfaceFlinger --latency`` for frame timing statistics.

    The output format is three lines of header (refresh period in ns) followed
    by rows of ``desired_vsync  actual_vsync  frame_ready`` nanosecond values.

    Returns
    -------
    dict
        * ``raw``            – unparsed string
        * ``refresh_ns``     – display refresh period in ns (int or None)
        * ``frame_count``    – number of valid frame intervals parsed (int)
        * ``avg_frame_ms``   – average frame render time in ms (float or None)
        * ``estimated_fps``  – estimated FPS derived from average frame time (float or None)
        * ``jank_count``     – frames that exceeded 2× the refresh period (int)
    """
    result: dict = {
        "raw": raw,
        "refresh_ns": None,
        "frame_count": 0,
        "avg_frame_ms": None,
        "estimated_fps": None,
        "jank_count": 0,
    }
    if not raw:
        return result

    lines = raw.strip().splitlines()
    if not lines:
        return result

    # First line is the refresh period in nanoseconds.
    try:
        result["refresh_ns"] = int(lines[0].strip())
    except (ValueError, IndexError):
        pass

    frame_times_ns: list[float] = []
    refresh_ns = result["refresh_ns"] or 16_666_667  # fallback: 60 Hz

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            desired_vsync = int(parts[0])
            frame_ready = int(parts[2])
            # Skip sentinel/zero rows emitted by SurfaceFlinger.
            if desired_vsync == 0 and frame_ready == 0:
                continue
            dt_ns = frame_ready - desired_vsync
            if dt_ns <= 0:
                continue
            frame_times_ns.append(float(dt_ns))
            if dt_ns > 2 * refresh_ns:
                result["jank_count"] += 1
        except (ValueError, IndexError):
            continue

    if frame_times_ns:
        avg_ns = sum(frame_times_ns) / len(frame_times_ns)
        result["frame_count"] = len(frame_times_ns)
        result["avg_frame_ms"] = round(avg_ns / 1_000_000, 2)
        if avg_ns > 0:
            result["estimated_fps"] = round(1_000_000_000 / avg_ns, 1)

    return result
