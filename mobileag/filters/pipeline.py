"""5-layer false positive elimination pipeline orchestrator."""

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
    """Runs each finding through 5 filter layers to eliminate false positives.

    Layers:
        1. Reachability — is the code actually reachable?
        2. Sanitizer — is input properly validated?
        3. Consensus — do multiple LLMs agree it's vulnerable?
        4. Historical — were similar past findings TP or FP?
        5. Confidence — aggregate all scores into final confidence

    Only findings that pass the confidence threshold are confirmed.
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
        self._threshold = self._settings.confidence_threshold

    async def filter_findings(
        self,
        findings: list[Finding],
        decompiled_path: str,
    ) -> list[Finding]:
        """Run all findings through the 5-layer filter pipeline.

        Args:
            findings: Raw findings from analysis agents.
            decompiled_path: Root of decompiled source tree.

        Returns:
            List of confirmed findings that passed all filters.
        """
        logger.info("Starting filter pipeline for %d findings", len(findings))
        confirmed: list[Finding] = []

        for i, finding in enumerate(findings):
            logger.info(
                "Filtering finding %d/%d: %s (%s)",
                i + 1, len(findings), finding.title, finding.cwe_id,
            )

            filter_scores: dict[str, float] = {}
            filter_reasons: dict[str, str] = {}

            # Layer 1: Reachability
            try:
                score, reason = await self._reachability.check(
                    finding_title=finding.title,
                    affected_component=finding.affected_component,
                    file_path=finding.file_path,
                    decompiled_path=decompiled_path,
                )
                filter_scores["reachability"] = score
                filter_reasons["reachability"] = reason
            except Exception as exc:
                logger.warning("Reachability filter error: %s", exc)
                filter_scores["reachability"] = 0.5

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
                filter_scores["sanitizer"] = score
                filter_reasons["sanitizer"] = reason
            except Exception as exc:
                logger.warning("Sanitizer filter error: %s", exc)
                filter_scores["sanitizer"] = 0.5

            # Layer 3: Consensus vote
            try:
                score, reason, votes = await self._consensus.check(
                    finding_title=finding.title,
                    finding_description=finding.description,
                    finding_cwe=finding.cwe_id,
                    code_snippet=finding.code_snippet,
                    affected_component=finding.affected_component,
                )
                filter_scores["consensus"] = score
                filter_reasons["consensus"] = reason
                finding.consensus_votes = votes
            except Exception as exc:
                logger.warning("Consensus filter error: %s", exc)
                filter_scores["consensus"] = 0.5

            # Layer 4: Historical match
            try:
                score, reason = await self._historical.check(
                    finding_title=finding.title,
                    finding_cwe=finding.cwe_id,
                    embedding=None,  # Embedding computed separately if Qdrant available
                )
                filter_scores["historical"] = score
                filter_reasons["historical"] = reason
            except Exception as exc:
                logger.warning("Historical filter error: %s", exc)
                filter_scores["historical"] = 0.5

            # Layer 5: Final confidence scoring
            final_confidence = self._scorer.score(filter_scores, finding.severity.value)

            # Update finding
            finding.filter_scores = filter_scores
            finding.confidence = final_confidence

            if final_confidence >= self._threshold:
                finding.status = FindingStatus.CONFIRMED
                confirmed.append(finding)
                logger.info(
                    "✅ CONFIRMED: %s (confidence: %.1f%%) — %s",
                    finding.title, final_confidence * 100, finding.cwe_id,
                )
            else:
                finding.status = FindingStatus.FALSE_POSITIVE
                finding.false_positive_reasons = [
                    f"{k}: {v}" for k, v in filter_reasons.items()
                ]
                logger.info(
                    "❌ FILTERED: %s (confidence: %.1f%% < threshold %.1f%%)",
                    finding.title, final_confidence * 100, self._threshold * 100,
                )

        logger.info(
            "Filter pipeline complete: %d/%d findings confirmed",
            len(confirmed), len(findings),
        )
        return confirmed
