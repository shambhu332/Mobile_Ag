"""MASVS mappings for vulnerabilities."""

import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

_MASVS_FILE = Path(__file__).parent.parent.parent / "data" / "masvs_mapping.json"

_masvs_data = {}

def get_masvs_description(masvs_id: str) -> str:
    """Get the description for a MASVS ID."""
    global _masvs_data
    if not _masvs_data:
        try:
            if _MASVS_FILE.exists():
                _masvs_data = json.loads(_MASVS_FILE.read_text())
        except Exception as e:
            logger.warning("Failed to load MASVS mapping: %s", e)
            
    return _masvs_data.get(masvs_id, "Unknown MASVS ID")
