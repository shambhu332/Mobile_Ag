"""Retired TLS bypass API retained only for a clear compatibility error."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class UnpinningConfig:
    """Legacy configuration shape; it cannot produce or execute a bypass."""
    target_package: str
    bypass_java: bool = False
    bypass_okhttp: bool = False
    bypass_boringssl: bool = False
    bypass_flutter: bool = False
    flutter_offset: Optional[str] = None


class UnpinningEngine:
    """Disabled by design; review Network Security Config instead."""

    def generate_script(self, config: UnpinningConfig) -> str:
        raise NotImplementedError(
            "TLS verification bypass generation is disabled; use static trust-configuration review"
        )
