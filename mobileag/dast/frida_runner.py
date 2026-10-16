"""Disabled runtime instrumentation compatibility surface.

MobileAg's safe assessment profile intentionally contains no Frida hook
payloads, trust bypasses, root evasion, or runtime secret-harvesting scripts.
Static configuration review and read-only process observation live elsewhere.
"""
from __future__ import annotations

from typing import Any, Optional

from mobileag.dast.adb_manager import ADBManager

HAS_NATIVE_FRIDA = False


class FridaRunner:
    """Compatibility adapter that refuses all instrumentation operations."""

    def __init__(self, adb: Optional[ADBManager] = None) -> None:
        self.adb = adb or ADBManager()

    async def is_frida_server_running(self, serial: str) -> Optional[bool]:
        """Return unknown; this adapter never probes a device."""
        return None

    async def start_frida_server(self, serial: str, server_path: str = "/data/local/tmp/frida-server") -> bool:
        """Refuse daemon startup; no root or shell command is issued."""
        return False

    async def execute_script_payload(
        self, serial: str, package_name: str, script_code: str, duration: float = 6.0,
    ) -> dict[str, Any]:
        """Refuse scripts; their contents are neither executed nor echoed."""
        return {"status": "disabled", "executed": False,
                "message": "Runtime instrumentation is disabled in the safe assessment profile"}

    def attach_and_instrument_session(
        self, package_name: str, script_code: str, on_message: Any = None,
        serial: Optional[str] = None,
    ) -> dict[str, Any]:
        """Refuse attachment; no process or script is touched."""
        return {"status": "disabled", "native_frida": False,
                "package_name": package_name,
                "message": "Runtime instrumentation is disabled in the safe assessment profile"}
