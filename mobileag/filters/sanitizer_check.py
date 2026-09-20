"""Sanitizer filter — detects whether input validation exists near the finding."""

import logging
from pathlib import Path
from typing import Optional

from config.llm_config import TaskType
from mobileag.llm.router import LLMRouter

logger = logging.getLogger(__name__)

# Patterns that indicate proper sanitization/validation
_SANITIZER_PATTERNS: list[str] = [
    # Input validation
    "TextUtils.isEmpty",
    "Pattern.compile",
    "Matcher.matches",
    "android.text.InputFilter",
    # Path sanitization
    "getCanonicalPath",
    "normalize()",
    "canonicalize",
    "FilenameUtils.getName",
    "contains(\"..\")",
    # SQL parameterization
    "ContentValues",
    "SQLiteStatement",
    "bindString",
    "?",  # Parameterized queries
    # Encoding
    "URLEncoder.encode",
    "Html.escapeHtml",
    "Uri.encode",
    "Base64.encode",
    # Crypto best practices
    "SecureRandom",
    "KeyStore.getInstance",
    "EncryptedSharedPreferences",
    # Permission checks
    "checkCallingPermission",
    "enforceCallingPermission",
    "checkSelfPermission",
]

_SANITIZER_SYSTEM_PROMPT = """You are a senior mobile security analyst. Analyze the code context below and determine if proper input sanitization or validation exists for the reported vulnerability.

Respond with ONLY a JSON object:
{
    "sanitized": true or false,
    "confidence": 0.0 to 1.0,
    "reasoning": "Explain what sanitization is present or missing"
}

Rules:
- Look for input validation, encoding, parameterized queries, path canonicalization
- Consider the FULL method/class context, not just the flagged line
- If the vulnerable pattern is wrapped in proper checks, mark as sanitized
- Return ONLY valid JSON, no markdown fences."""


class SanitizerFilter:
    """Checks whether proper input sanitization exists near a finding.

    Combines pattern matching with LLM-based contextual analysis.
    """

    def __init__(self, router: LLMRouter):
        self._router = router

    async def check(
        self,
        finding_title: str,
        finding_cwe: str,
        file_path: str,
        line_number: Optional[int],
        code_snippet: str,
        decompiled_path: str,
    ) -> tuple[float, str]:
        """Check if the code around a finding has proper sanitization.

        Args:
            finding_title: Title of the finding.
            finding_cwe: CWE identifier.
            file_path: Path to the source file.
            line_number: Line number of the finding.
            code_snippet: Code snippet from the finding.
            decompiled_path: Root of decompiled source.

        Returns:
            Tuple of (score 0.0–1.0, reason).
            Low score = sanitization detected (likely false positive).
        """
        # Get surrounding code context
        context = self._get_code_context(file_path, line_number, decompiled_path)

        if not context:
            return 0.6, "Could not read code context — assuming no sanitization"

        # Quick pattern check first
        pattern_score, pattern_reason = self._pattern_check(context, finding_cwe)

        if pattern_score <= 0.3:
            # Strong sanitization signals found — skip LLM call
            return pattern_score, pattern_reason

        # For ambiguous cases, ask LLM
        llm_score, llm_reason = await self._llm_check(context, finding_title, finding_cwe)

        # Blend: give more weight to LLM for ambiguous cases
        final_score = pattern_score * 0.4 + llm_score * 0.6
        combined_reason = f"Pattern: {pattern_reason} | LLM: {llm_reason}"

        return final_score, combined_reason

    def _get_code_context(
        self,
        file_path: str,
        line_number: Optional[int],
        decompiled_path: str,
    ) -> str:
        """Read surrounding code context (±30 lines around the finding)."""
        if not file_path:
            return ""

        fp = Path(file_path)
        if not fp.exists():
            # Try relative to decompiled_path
            fp = Path(decompiled_path) / file_path
            if not fp.exists():
                return ""

        try:
            lines = fp.read_text(errors="replace").splitlines()
        except OSError:
            return ""

        if line_number and line_number > 0:
            start = max(0, line_number - 31)
            end = min(len(lines), line_number + 30)
            return "\n".join(lines[start:end])

        # No line number — return first 100 lines
        return "\n".join(lines[:100])

    def _pattern_check(self, code_context: str, cwe: str) -> tuple[float, str]:
        """Quick pattern-based sanitization detection."""
        found_patterns: list[str] = []
        for pattern in _SANITIZER_PATTERNS:
            if pattern in code_context:
                found_patterns.append(pattern)

        if not found_patterns:
            return 0.8, "No sanitization patterns detected"

        if len(found_patterns) >= 3:
            return 0.2, f"Multiple sanitization patterns found: {', '.join(found_patterns[:5])}"
        elif len(found_patterns) >= 1:
            return 0.5, f"Some sanitization present: {', '.join(found_patterns)}"

        return 0.7, "Weak sanitization signals"

    async def _llm_check(
        self,
        code_context: str,
        finding_title: str,
        finding_cwe: str,
    ) -> tuple[float, str]:
        """Ask LLM whether proper sanitization exists."""
        import json

        user_prompt = f"""## Vulnerability Found
Title: {finding_title}
CWE: {finding_cwe}

## Code Context
```java
{code_context[:4000]}
```

Does this code have proper input sanitization or validation for the reported vulnerability?"""

        try:
            response = await self._router.route(
                task_type=TaskType.CODE_REVIEW,
                system_prompt=_SANITIZER_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.1,
            )

            if not response.success:
                return 0.6, f"LLM check failed: {response.error}"

            data = json.loads(self._clean_json(response.content))
            is_sanitized = bool(data.get("sanitized", False))
            confidence = float(data.get("confidence", 0.5))
            reasoning = str(data.get("reasoning", ""))

            if is_sanitized:
                score = max(0.1, 1.0 - confidence)  # High confidence sanitized = low vuln score
            else:
                score = min(0.95, 0.5 + confidence * 0.5)  # Confirmed vulnerable

            return score, reasoning

        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.warning("Failed to parse LLM sanitizer response: %s", exc)
            return 0.6, "Could not parse LLM analysis"

    @staticmethod
    def _clean_json(text: str) -> str:
        """Strip markdown fences from LLM JSON output."""
        content = text.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1] if "\n" in content else content[3:]
        if content.endswith("```"):
            content = content.rsplit("```", 1)[0]
        content = content.strip()
        if content.startswith("json"):
            content = content[4:].strip()
        return content
