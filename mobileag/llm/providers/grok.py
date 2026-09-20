"""xAI Grok LLM provider using OpenAI-compatible API."""

import logging
from typing import Optional

try:
    from openai import AsyncOpenAI
except (ImportError, AttributeError):
    AsyncOpenAI = None

from mobileag.llm.providers.base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class GrokProvider(BaseLLMProvider):
    """xAI Grok provider via OpenAI-compatible endpoint."""

    DEFAULT_BASE_URL = "https://api.x.ai/v1"

    def __init__(
        self,
        api_key: str,
        model: str = "grok-2",
        base_url: Optional[str] = None,
        **kwargs,
    ):
        url = base_url or self.DEFAULT_BASE_URL
        super().__init__(api_key=api_key, model=model, base_url=url, **kwargs)
        if AsyncOpenAI is None:
            raise ImportError(
                "The 'openai' package is required to use GrokProvider. "
                "Install it via: pip install openai"
            )
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=url,
            timeout=self.timeout,
        )

    @property
    def name(self) -> str:
        return f"grok ({self.model})"

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Generate a response via the xAI Grok API."""
        tokens = max_tokens or self.max_tokens

        try:
            with self._measure_time() as timer:
                response = await self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=temperature,
                    max_tokens=tokens,
                )

            choice = response.choices[0]
            text = choice.message.content or ""
            usage = response.usage

            self._track_request(True)
            logger.info(
                "Grok [%s] responded in %.0fms (%d tokens)",
                self.model, timer.elapsed_ms,
                usage.total_tokens if usage else 0,
            )

            return LLMResponse(
                content=text,
                model=self.model,
                provider="grok",
                prompt_tokens=usage.prompt_tokens if usage else 0,
                completion_tokens=usage.completion_tokens if usage else 0,
                total_tokens=usage.total_tokens if usage else 0,
                latency_ms=timer.elapsed_ms,
                success=True,
            )

        except Exception as exc:
            self._track_request(False)
            logger.error("Grok [%s] error: %s", self.model, exc)
            return LLMResponse(
                content="",
                model=self.model,
                provider="grok",
                latency_ms=0,
                success=False,
                error=str(exc),
            )
