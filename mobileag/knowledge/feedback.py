"""
Self-learning feedback loop to adjust model confidences based on historical verdicts.
"""

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Dict, Any

from mobileag.knowledge.qdrant_store import PatternMemory
from mobileag.knowledge.neo4j_graph import AttackGraph
from mobileag.security.privacy import redact

logger = logging.getLogger(__name__)

_MAX_TRAINING_EXPORT_ROWS = 10_000
_MAX_TRAINING_EXPORT_PAGES = 100
_MAX_TRAINING_EXPORT_BYTES = 16 * 1024 * 1024

class FeedbackEngine:
    """Manages the feedback loop by utilizing Qdrant memory and Neo4j graph data."""
    
    def __init__(self, qdrant: PatternMemory, graph: AttackGraph):
        self.qdrant = qdrant
        self.graph = graph

    async def record_feedback(self, finding_id: str, scan_id: str, verdict: str, notes: str = '') -> None:
        """
        Records TP/FP/DUPLICATE verdict.
        Updates both Qdrant pattern memory and Neo4j graph if needed.
        """
        is_tp = (verdict.upper() == 'TP')
        await self.qdrant.mark_verdict(finding_id, is_true_positive=is_tp)
        logger.info(f"Recorded feedback for finding {finding_id}: {verdict}")

    async def get_confidence_adjustment(self, finding_embedding: list[float]) -> float:
        """
        Returns confidence delta based on historical similar findings.
        Range: -0.3 to +0.3.
        """
        stats = await self.qdrant.get_historical_verdicts(finding_embedding)
        total = stats.get("total_relevant", 0)
        
        if total < 3:
            return 0.0  # Not enough data to adjust

        tp_rate = stats.get("tp_rate", 0.5)
        
        # Calculate adjustment: map [0.0, 1.0] to [-0.3, 0.3]
        adjustment = (tp_rate - 0.5) * 0.6
        return round(adjustment, 2)

    async def get_pattern_stats(self) -> Dict[str, Any]:
        """
        Overall TP/FP rates by CWE, severity.
        Requires retrieving data from Qdrant and aggregating.
        """
        if not self.qdrant._connected or not self.qdrant.client:
            return {}

        try:
            scroll_result = await self.qdrant.client.scroll(
                collection_name=self.qdrant.collection_name,
                limit=1000  # Assume up to 1000 past findings for stats
            )
            points, _ = scroll_result
            
            stats = {"cwe": {}, "severity": {}}
            for p in points:
                payload = p.payload
                cwe = payload.get("cwe", "UNKNOWN")
                sev = payload.get("severity", "UNKNOWN")
                is_tp = payload.get("is_true_positive")
                
                if is_tp is None:
                    continue
                    
                if cwe not in stats["cwe"]:
                    stats["cwe"][cwe] = {"tp": 0, "fp": 0}
                if sev not in stats["severity"]:
                    stats["severity"][sev] = {"tp": 0, "fp": 0}
                    
                if is_tp:
                    stats["cwe"][cwe]["tp"] += 1
                    stats["severity"][sev]["tp"] += 1
                else:
                    stats["cwe"][cwe]["fp"] += 1
                    stats["severity"][sev]["fp"] += 1
                    
            return stats
        except Exception as e:
            logger.error(f"Failed to get pattern stats: {e}")
            return {}

    async def export_training_data(self, output_path: str | Path) -> None:
        """
        Exports labeled data for future model fine-tuning (JSON lines format).
        """
        if not self.qdrant._connected or not self.qdrant.client:
            logger.warning("Qdrant not connected, cannot export training data.")
            return

        temporary_path = None
        try:
            output = Path(output_path)
            output.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary_path = tempfile.mkstemp(
                prefix=f".{output.name}.", suffix=".tmp", dir=output.parent,
            )
            rows = 0
            total_bytes = 0
            offset = None
            with os.fdopen(fd, "wb") as stream:
                for _page in range(_MAX_TRAINING_EXPORT_PAGES):
                    points, offset = await self.qdrant.client.scroll(
                        collection_name=self.qdrant.collection_name,
                        limit=100,
                        offset=offset,
                    )
                    for point in points:
                        payload = getattr(point, "payload", None)
                        if not isinstance(payload, dict) or payload.get("is_true_positive") is None:
                            continue
                        row = json.dumps(redact(payload), ensure_ascii=True, allow_nan=False,
                                         separators=(",", ":")).encode("utf-8") + b"\n"
                        rows += 1
                        total_bytes += len(row)
                        if rows > _MAX_TRAINING_EXPORT_ROWS or total_bytes > _MAX_TRAINING_EXPORT_BYTES:
                            raise ValueError("Training data export exceeds its output limits")
                        stream.write(row)
                    if offset is None:
                        break
                else:
                    if offset is not None:
                        raise ValueError("Training data export exceeds its page limit")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, output)
            temporary_path = None
            logger.info("Exported %d redacted training records to %s", rows, output)
        except Exception as e:
            logger.error(f"Failed to export training data: {e}")
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass
