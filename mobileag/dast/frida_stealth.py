"""Retired compatibility surface for instrumentation concealment features."""
from __future__ import annotations


class FridaStealthHarness:
    """Stealth/anti-detection support is intentionally unavailable."""

    def generate_random_config(self):
        raise NotImplementedError("Stealthy daemon deployment is disabled")

    def get_stealth_preamble_script(self) -> str:
        raise NotImplementedError("Anti-detection hook generation is disabled")
