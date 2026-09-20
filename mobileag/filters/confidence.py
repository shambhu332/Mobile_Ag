"""Final confidence scoring — aggregates all filter layer scores."""

import logging

logger = logging.getLogger(__name__)

# Default weights for each filter layer
_DEFAULT_WEIGHTS: dict[str, float] = {
    "reachability": 0.15,
    "sanitizer": 0.25,
    "consensus": 0.35,
    "historical": 0.15,
    "severity_bonus": 0.10,
}

_SEVERITY_BONUS: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.3,
    "INFO": 0.1,
}


class ConfidenceScorer:
    """Computes a final confidence score by aggregating all filter layer scores.

    Each layer contributes a weighted portion to the final score.
    A severity bonus slightly boosts higher-severity findings.
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
        severity: str,
    ) -> float:
        """Compute the final confidence score.

        Args:
            filter_scores: Scores from each filter layer (0.0–1.0).
                Expected keys: reachability, sanitizer, consensus, historical.
            severity: Finding severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO).

        Returns:
            Final confidence score between 0.0 and 1.0.
        """
        weighted_sum = 0.0
        total_weight = 0.0

        for layer_name, weight in self._weights.items():
            if layer_name == "severity_bonus":
                continue  # Handled separately

            layer_score = filter_scores.get(layer_name, 0.5)  # Default to neutral
            weighted_sum += layer_score * weight
            total_weight += weight

        # Add severity bonus
        sev_weight = self._weights.get("severity_bonus", 0.10)
        sev_score = _SEVERITY_BONUS.get(severity.upper(), 0.3)
        weighted_sum += sev_score * sev_weight
        total_weight += sev_weight

        if total_weight <= 0:
            return 0.5

        final = weighted_sum / total_weight
        return round(max(0.0, min(1.0, final)), 3)
