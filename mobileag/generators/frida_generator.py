"""Retired compatibility surface for generated runtime hook scripts."""
from __future__ import annotations

from typing import Any


class FridaGenerator:
    """Refuses code generation; scan results never contain hook payloads."""

    def __init__(self, router: Any = None):
        self._router = router

    async def generate(self, finding: Any, app_info: dict) -> str:
        raise NotImplementedError(
            "Runtime hook generation is disabled; use static evidence and analyst-reviewed plans"
        )

    async def generate_batch(self, findings: list[Any], app_info: dict) -> list[dict[str, Any]]:
        return []
