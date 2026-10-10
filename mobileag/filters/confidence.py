"""Heuristic review-priority calculation; this is not a probability or proof score."""

import logging

logger = logging.getLogger(__name__)

# Relative ranking weights for available heuristic signals only. These weights
# are not statistically calibrated and must never be presented as confidence.
_DEFAULT_WEIGHTS: dict[str, float] = {
    "reachability": 0.15,
    "sanitizer": 0.25,
    "consensus": 0.35,
    "historical": 0.15,
}


class ConfidenceScorer:
    """Rank candidates using only available heuristic signals.

    The legacy class name and ``score`` API remain for compatibility. The
    returned value is a review-priority index, not calibrated confidence.
    Missing signals are omitted instead of being imputed as neutral evidence.
    """

    def __init__(self, weights: dict[str, float] | None = None):
        """Initialize with custom or default weights.

        Args:
            weights: Optional dict mapping layer names to weights (must sum to ~1.0).
        """
        self._weights = weights or _DEFAULT_WEIGHTS

    def score(
        self,
        filter_scores: dict[str, float],
        severity: str | None = None,
    ) -> float:
        """Compute a heuristic review-priority index.

        Args:
            filter_scores: Available evidence-bearing heuristic scores (0.0–1.0).
            severity: Deprecated compatibility argument; intentionally ignored.

        Returns:
            Uncalibrated ranking index between 0.0 and 1.0.
        """
        available = [(self._weights[name], value) for name, value in filter_scores.items()
                     if name in self._weights and isinstance(value, (int, float))]
        total_weight = sum(weight for weight, _ in available)
        if total_weight <= 0:
            return 0.0
        weighted_sum = sum(weight * max(0.0, min(1.0, float(value)))
                           for weight, value in available)
        return round(weighted_sum / total_weight, 3)
