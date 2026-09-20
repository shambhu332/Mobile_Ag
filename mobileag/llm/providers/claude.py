"""Anthropic Claude LLM provider using the anthropic SDK."""

import logging
from typing import Optional

try:
    from anthropic import AsyncAnthropic
except (ImportError, AttributeError):
    AsyncAnthropic = None

from mobileag.llm.providers.base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class ClaudeProvider(BaseLLMProvider):
    """Anthropic Claude provider (Claude Sonnet 4, etc.)."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
        **kwargs,
    ):
        super().__init__(api_key=api_key, model=model, **kwargs)
        if AsyncAnthropic is None:
            raise ImportError(
                "The 'anthropic' package is required to use ClaudeProvider. "
                "Install it via: pip install anthropic"
            )
        self._client = AsyncAnthropic(
            api_key=api_key,
            timeout=self.timeout,
        )

    @property
    def name(self) -> str:
        return f"claude ({self.model})"

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Generate a response using the Anthropic messages API."""
        tokens = max_tokens or self.max_tokens

        try:
            with self._measure_time() as timer:
                response = await self._client.messages.create(
                    model=self.model,
                    max_tokens=tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=[
                        {"role": "user", "content": user_prompt},
                    ],
                )

            # Extract text from content blocks
            text_blocks = [
                block.text for block in response.content
                if hasattr(block, "text")
            ]
            text = "\n".join(text_blocks)

            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens

            self._track_request(True)
            logger.info(
                "Claude [%s] responded in %.0fms (%d in, %d out)",
                self.model, timer.elapsed_ms, input_tokens, output_tokens,
            )

            return LLMResponse(
                content=text,
                model=self.model,
                provider="claude",
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                latency_ms=timer.elapsed_ms,
                success=True,
            )

        except Exception as exc:
            self._track_request(False)
            logger.error("Claude [%s] error: %s", self.model, exc)
            return LLMResponse(
                content="",
                model=self.model,
                provider="claude",
                latency_ms=0,
                success=False,
                error=str(exc),
            )
