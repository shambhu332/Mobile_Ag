"""Consensus vote filter — uses multi-LLM agreement to validate findings."""

import logging
from typing import Optional

from mobileag.llm.consensus import ConsensusVoter, ConsensusResult

logger = logging.getLogger(__name__)


class ConsensusFilter:
    """Validates findings by sending them to multiple LLMs and checking
    whether they agree the vulnerability is real.
    """

    def __init__(self, voter: ConsensusVoter):
        self._voter = voter

    async def check(
        self,
        finding_title: str,
        finding_description: str,
        finding_cwe: str,
        code_snippet: str,
        affected_component: str,
    ) -> tuple[float, str, dict[str, bool]]:
        """Run consensus voting on a finding.

        Args:
            finding_title: Title of the finding.
            finding_description: Full description.
            finding_cwe: CWE identifier.
            code_snippet: Relevant code.
            affected_component: Affected class/component.

        Returns:
            Tuple of (score 0.0–1.0, combined_reasoning, votes_dict).
        """
        question = (
            f"Is this a real, exploitable vulnerability?\n\n"
            f"**Title:** {finding_title}\n"
            f"**CWE:** {finding_cwe}\n"
            f"**Component:** {affected_component}\n"
            f"**Description:** {finding_description}\n"
        )

        code_context = code_snippet[:3000] if code_snippet else "No code snippet available"

        try:
            result: ConsensusResult = await self._voter.vote(
                question=question,
                code_context=code_context,
                num_voters=3,
            )
        except Exception as exc:
            logger.warning("Consensus vote failed: %s", exc)
            return 0.5, f"Consensus voting error: {exc}", {}

        # Map consensus to score
        score = self._result_to_score(result)
        votes = {
            provider: vote.vulnerable
            for provider, vote in result.votes.items()
        }

        return score, result.combined_reasoning, votes

    @staticmethod
    def _result_to_score(result: ConsensusResult) -> float:
        """Convert consensus result to a confidence score."""
        if result.total_voters == 0:
            return 0.5

        ratio = result.agreement_ratio

        if result.is_vulnerable:
            # Majority says vulnerable
            if ratio >= 1.0:
                return 1.0   # Unanimous agreement
            elif ratio >= 0.67:
                return 0.8   # Strong majority
            else:
                return 0.6   # Bare majority
        else:
            # Majority says NOT vulnerable
            if ratio <= 0.0:
                return 0.1   # Unanimous: not vulnerable
            elif ratio <= 0.33:
                return 0.25  # Strong majority: not vulnerable
            else:
                return 0.4   # Split opinion
