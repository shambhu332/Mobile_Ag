"""Multi-LLM consensus voting system.

Sends the same analysis prompt to multiple LLMs and aggregates
their votes to reduce false positives and hallucinations.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from config.llm_config import TaskType
from mobileag.llm.router import LLMRouter

logger = logging.getLogger(__name__)

VOTE_SYSTEM_PROMPT = """You are a senior mobile security analyst. You will be given a code snippet 
and a security question. Analyze the code carefully and respond with ONLY a JSON object:

{
    "vulnerable": true or false,
    "confidence": 0.0 to 1.0,
    "cwe": "CWE-XXX" or "N/A",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "NONE",
    "reasoning": "Your detailed reasoning in 2-3 sentences"
}

Rules:
- Be conservative. Only mark as vulnerable if you are confident.
- If the code has proper sanitization or validation, mark as NOT vulnerable.
- Consider the FULL context, not just pattern matching.
- Return ONLY valid JSON, no markdown fences."""


@dataclass
class VoteDetail:
    """Individual vote from a single LLM provider."""
    provider: str
    vulnerable: bool
    confidence: float
    reasoning: str
    cwe: str = "N/A"
    severity: str = "NONE"
    raw_response: str = ""


@dataclass
class ConsensusResult:
    """Aggregated result from multi-LLM consensus voting."""
    is_vulnerable: bool
    votes: dict[str, VoteDetail] = field(default_factory=dict)
    agreement_ratio: float = 0.0
    combined_confidence: float = 0.0
    combined_reasoning: str = ""
    total_voters: int = 0
    vulnerable_votes: int = 0


class ConsensusVoter:
    """Sends analysis questions to multiple LLMs and aggregates votes.

    Usage:
        voter = ConsensusVoter(router, min_votes=2)
        result = await voter.vote(
            question="Is this ContentProvider vulnerable to path traversal?",
            code_context="public ParcelFileDescriptor openFile(Uri uri, String mode) {...}"
        )
        if result.is_vulnerable:
            print(f"Confirmed! Agreement: {result.agreement_ratio:.0%}")
    """

    def __init__(self, router: LLMRouter, min_votes: int = 2):
        self._router = router
        self._min_votes = min_votes

    async def vote(
        self,
        question: str,
        code_context: str,
        num_voters: int = 3,
    ) -> ConsensusResult:
        """Send the same question to multiple LLMs and aggregate votes.

        Args:
            question: Security analysis question.
            code_context: The code snippet to analyze.
            num_voters: Number of LLMs to query (default 3).

        Returns:
            ConsensusResult with aggregated votes and final decision.
        """
        user_prompt = f"""## Security Question
{question}

## Code Context
```
{code_context}
```

Analyze the code above and respond with a JSON verdict."""

        # Send to multiple providers concurrently
        responses = await self._router.route_to_multiple(
            task_type=TaskType.CONSENSUS_VOTE,
            system_prompt=VOTE_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            count=num_voters,
            temperature=0.1,
        )

        # Parse each response into a VoteDetail
        votes: dict[str, VoteDetail] = {}
        for resp in responses:
            if not resp.success:
                logger.warning("Vote failed from %s: %s", resp.provider, resp.error)
                continue

            vote = self._parse_vote(resp.provider, resp.content)
            if vote:
                votes[resp.provider] = vote

        # Aggregate votes
        return self._aggregate_votes(votes)

    def _parse_vote(self, provider: str, raw_content: str) -> Optional[VoteDetail]:
        """Parse an LLM response into a structured vote."""
        try:
            # Strip markdown fences if present
            content = raw_content.strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
            if content.endswith("```"):
                content = content.rsplit("```", 1)[0]
            content = content.strip()

            # Handle json prefix
            if content.startswith("json"):
                content = content[4:].strip()

            data = json.loads(content)

            return VoteDetail(
                provider=provider,
                vulnerable=bool(data.get("vulnerable", False)),
                confidence=float(data.get("confidence", 0.5)),
                reasoning=str(data.get("reasoning", "")),
                cwe=str(data.get("cwe", "N/A")),
                severity=str(data.get("severity", "NONE")),
                raw_response=raw_content,
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning("Failed to parse vote from %s: %s", provider, e)
            return None

    def _aggregate_votes(self, votes: dict[str, VoteDetail]) -> ConsensusResult:
        """Aggregate individual votes into a consensus decision."""
        if not votes:
            return ConsensusResult(
                is_vulnerable=False,
                combined_reasoning="No valid votes received from any provider.",
            )

        total = len(votes)
        vuln_count = sum(1 for v in votes.values() if v.vulnerable)
        agreement = vuln_count / total if total > 0 else 0.0

        # Majority vote: vulnerable if >= min_votes agree
        is_vulnerable = vuln_count >= self._min_votes

        # Combined confidence: weighted average of agreeing voters
        if is_vulnerable:
            agreeing = [v for v in votes.values() if v.vulnerable]
            avg_confidence = sum(v.confidence for v in agreeing) / len(agreeing)
        else:
            disagreeing = [v for v in votes.values() if not v.vulnerable]
            avg_confidence = sum(v.confidence for v in disagreeing) / len(disagreeing) if disagreeing else 0.0

        # Build combined reasoning
        reasons = []
        for provider, vote in votes.items():
            verdict = "VULNERABLE" if vote.vulnerable else "NOT VULNERABLE"
            reasons.append(
                f"[{provider}] {verdict} (confidence: {vote.confidence:.0%}): {vote.reasoning}"
            )

        return ConsensusResult(
            is_vulnerable=is_vulnerable,
            votes=votes,
            agreement_ratio=agreement,
            combined_confidence=avg_confidence,
            combined_reasoning="\n".join(reasons),
            total_voters=total,
            vulnerable_votes=vuln_count,
        )
