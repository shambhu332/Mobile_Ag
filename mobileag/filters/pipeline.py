"""Advisory candidate-ranking pipeline; stages do not prove or eliminate findings."""

import logging
from typing import Optional, Any

from config.settings import Settings
from mobileag.reporting.finding import Finding, FindingStatus
from mobileag.llm.router import LLMRouter
from mobileag.llm.consensus import ConsensusVoter
from mobileag.filters.reachability import ReachabilityFilter
from mobileag.filters.sanitizer_check import SanitizerFilter
from mobileag.filters.consensus_vote import ConsensusFilter
from mobileag.filters.historical_match import HistoricalFilter
from mobileag.filters.confidence import ConfidenceScorer

logger = logging.getLogger(__name__)


class FilterPipeline:
    """Attach optional heuristic ranking signals to findings.

    Stages are advisory signals only. They do not validate exploitability or
    silently discard unverified candidates.

    All findings remain unverified review candidates; low heuristic scores never silently discard them.
    """

    def __init__(
        self,
        router: LLMRouter,
        qdrant: Optional[Any] = None,
        consensus_voter: Optional[ConsensusVoter] = None,
        settings: Optional[Settings] = None,
    ):
        self._settings = settings or Settings()
        self._reachability = ReachabilityFilter()
        self._sanitizer = SanitizerFilter(router)
        self._consensus = ConsensusFilter(
            consensus_voter or ConsensusVoter(router, min_votes=self._settings.consensus_min_votes)
        )
        self._historical = HistoricalFilter(qdrant)
        self._scorer = ConfidenceScorer()
        self._threshold = (self._settings.confidence_threshold
                           if self._settings.confidence_threshold is not None
                           else self._settings.review_priority_threshold)

    async def filter_findings(
        self,
        findings: list[Finding],
        decompiled_path: str,
    ) -> list[Finding]:
        """Attach available heuristic signals and retain candidates for review.

        Args:
            findings: Raw findings from analysis agents.
            decompiled_path: Root of decompiled source tree.

        Returns:
            All review candidates, ranked by heuristic scores; low scores do not prove a false positive.
        """
        logger.info("Starting filter pipeline for %d findings", len(findings))
        candidates: list[Finding] = []

        for i, finding in enumerate(findings):
            logger.info(
                "Filtering finding %d/%d: %s (%s)",
                i + 1, len(findings), finding.title, finding.cwe_id,
            )

            filter_scores: dict[str, float] = {}
            filter_reasons: dict[str, str] = {}
            filter_stages: dict[str, dict[str, str]] = {}

            def record(name: str, score: float, reason: str) -> None:
                unavailable = any(token in reason.lower() for token in (
                    "insufficient data", "not found", "could not read", "no historical",
                    "no embedding", "not configured", "disabled", "offline",
                    "check failed", "could not parse", "unknown:",
                ))
                status = "unavailable" if unavailable else "evaluated_heuristically"
                filter_stages[name] = {"status": status, "reason": reason}
                filter_reasons[name] = reason
                if not unavailable:
                    filter_scores[name] = score

            # Layer 1: Reachability
            try:
                if not self._settings.enable_reachability_filter:
                    raise ValueError("Reachability disabled by operator")
                score, reason = await self._reachability.check(
                    finding_title=finding.title,
                    affected_component=finding.affected_component,
                    file_path=finding.file_path,
                    decompiled_path=decompiled_path,
                )
                record("reachability", score, reason)
            except Exception as exc:
                logger.warning("Reachability filter error: %s", exc)
                filter_stages["reachability"] = {"status": "failed", "reason": type(exc).__name__}

            # Layer 2: Sanitizer check
            try:
                score, reason = await self._sanitizer.check(
                    finding_title=finding.title,
                    finding_cwe=finding.cwe_id,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    code_snippet=finding.code_snippet,
                    decompiled_path=decompiled_path,
                )
                record("sanitizer", score, reason)
            except Exception as exc:
                logger.warning("Sanitizer filter error: %s", exc)
                filter_stages["sanitizer"] = {"status": "failed", "reason": type(exc).__name__}

            # Layer 3: Consensus vote
            try:
                if not self._settings.enable_consensus_voting or self._settings.offline:
                    raise ValueError("Consensus disabled or offline")
                score, reason, votes = await self._consensus.check(
                    finding_title=finding.title,
                    finding_description=finding.description,
                    finding_cwe=finding.cwe_id,
                    code_snippet=finding.code_snippet,
                    affected_component=finding.affected_component,
                )
                finding.consensus_votes = votes
                if votes:
                    record("consensus", score, reason)
                else:
                    filter_stages["consensus"] = {"status": "unavailable", "reason": "No valid model votes were returned"}
                    filter_reasons["consensus"] = "No valid model votes were returned"
            except Exception as exc:
                logger.warning("Consensus filter error: %s", exc)
                reason = "Consensus disabled or offline" if not self._settings.enable_consensus_voting or self._settings.offline else type(exc).__name__
                filter_stages["consensus"] = {"status": "not_run" if "disabled" in reason.lower() or "offline" in reason.lower() else "failed", "reason": reason}
                filter_reasons["consensus"] = reason

            # Layer 4: Historical match
            try:
                score, reason = await self._historical.check(
                    finding_title=finding.title,
                    finding_cwe=finding.cwe_id,
                    embedding=None,  # Embedding computed separately if Qdrant available
                )
                record("historical", score, reason)
            except Exception as exc:
                logger.warning("Historical filter error: %s", exc)
                filter_stages["historical"] = {"status": "failed", "reason": type(exc).__name__}

            # Ranking only: severity is impact, not evidence of exploitability.
            review_priority = self._scorer.score(filter_scores)

            finding.metadata["filter_reasons"] = filter_reasons
            finding.metadata["filter_stages"] = filter_stages
            finding.metadata["assessment"] = "Heuristic review priority, not calibrated confidence or exploit verification"
            finding.filter_scores = filter_scores
            finding.review_priority = review_priority
            finding.metadata.pop("below_review_priority_threshold", None)

            if review_priority >= self._threshold:
                finding.metadata["review_priority_disposition"] = "above_threshold"
                candidates.append(finding)
                logger.info(
                    "CANDIDATE: %s (heuristic review priority: %.1f%%) — %s",
                    finding.title, review_priority * 100, finding.cwe_id,
                )
            else:
                finding.metadata["below_review_priority_threshold"] = True
                finding.metadata["review_priority_disposition"] = "below_threshold_candidate_retained"
                candidates.append(finding)  # Never silently discard an unverified candidate.
                logger.info(
                    "LOW-PRIORITY CANDIDATE RETAINED: %s (heuristic review priority: %.1f%% < threshold %.1f%%)",
                    finding.title, review_priority * 100, self._threshold * 100,
                )

        logger.info(
            "Filter pipeline complete: %d/%d findings retained",
            len(candidates), len(findings),
        )
        return candidates
