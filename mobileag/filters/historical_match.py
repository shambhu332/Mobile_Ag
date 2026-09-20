"""Historical match filter — uses Qdrant vector similarity to learn from past scans."""

import logging
from typing import Optional, Any

logger = logging.getLogger(__name__)


class HistoricalFilter:
    """Checks if similar findings in the past were true or false positives.

    Uses Qdrant vector similarity search to find past findings with
    matching patterns and adjusts confidence accordingly.
    """

    def __init__(self, qdrant: Optional[Any] = None):
        """Initialize with optional Qdrant PatternMemory instance.

        Args:
            qdrant: PatternMemory instance, or None if Qdrant is unavailable.
        """
        self._qdrant = qdrant

    async def check(
        self,
        finding_title: str,
        finding_cwe: str,
        embedding: Optional[list[float]] = None,
    ) -> tuple[float, str]:
        """Check historical verdicts for similar findings.

        Args:
            finding_title: Title of the current finding.
            finding_cwe: CWE identifier.
            embedding: Vector embedding of the finding (384-dim).

        Returns:
            Tuple of (score 0.0–1.0, reason).
            High score = past similar findings were TP.
            Low score = past similar findings were FP.
        """
        if self._qdrant is None:
            return 0.5, "No historical data available (Qdrant not configured)"

        if embedding is None:
            return 0.5, "No embedding provided for similarity search"

        try:
            verdicts = await self._qdrant.get_historical_verdicts(embedding)
        except Exception as exc:
            logger.warning("Historical lookup failed: %s", exc)
            return 0.5, f"Historical lookup error: {exc}"

        if not verdicts or verdicts.get("total", 0) == 0:
            return 0.5, f"No historical matches for {finding_cwe} findings"

        tp_count = verdicts.get("true_positive", 0)
        fp_count = verdicts.get("false_positive", 0)
        total = tp_count + fp_count

        if total == 0:
            return 0.5, "Historical matches found but no verdicts recorded"

        tp_ratio = tp_count / total
        avg_similarity = verdicts.get("avg_similarity", 0.0)

        # Weight the historical signal by similarity
        if avg_similarity >= 0.85:
            weight = 1.0  # Very similar — trust history fully
        elif avg_similarity >= 0.7:
            weight = 0.7
        else:
            weight = 0.4  # Less similar — partial weight

        # Blend toward 0.5 based on weight
        raw_score = tp_ratio
        score = 0.5 + (raw_score - 0.5) * weight

        if tp_ratio >= 0.8:
            reason = (
                f"Historical pattern: {tp_count}/{total} similar findings were TRUE POSITIVES "
                f"(avg similarity: {avg_similarity:.0%}) — high confidence"
            )
        elif tp_ratio <= 0.2:
            reason = (
                f"Historical pattern: {fp_count}/{total} similar findings were FALSE POSITIVES "
                f"(avg similarity: {avg_similarity:.0%}) — likely FP"
            )
        else:
            reason = (
                f"Mixed history: {tp_count} TP, {fp_count} FP out of {total} similar findings "
                f"(avg similarity: {avg_similarity:.0%})"
            )

        return round(score, 3), reason
