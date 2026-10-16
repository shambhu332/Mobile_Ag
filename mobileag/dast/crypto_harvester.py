"""Safe parser for bounded crypto metadata; runtime hook generation is retired.

Raw keys, IVs, plaintext, database credentials, and payload previews are never
accepted into the returned event model.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class HarvestedCryptoEvent:
    timestamp: str
    operation: str
    algorithm: str


class CryptoHarvester:
    """Metadata-only parser retained for offline fixtures, not data harvesting."""

    def generate_hook_script(self) -> str:
        raise NotImplementedError(
            "Crypto hook generation is disabled; raw key, IV, and plaintext collection is out of scope"
        )

    def parse_event(self, message: Dict[str, Any]) -> Optional[HarvestedCryptoEvent]:
        """Parse only allowlisted algorithm/operation labels from a synthetic event."""
        if not isinstance(message, dict) or message.get("type") != "crypto_event":
            return None
        operation = message.get("operation")
        algorithm = message.get("algorithm")
        if not isinstance(operation, str) or not isinstance(algorithm, str):
            return None
        operation = operation[:32]
        algorithm = algorithm[:96]
        import datetime
        return HarvestedCryptoEvent(
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            operation=operation,
            algorithm=algorithm,
        )
