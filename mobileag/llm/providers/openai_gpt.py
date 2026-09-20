"""OpenAI GPT provider using the openai SDK."""

import logging
from typing import Optional

try:
    from openai import AsyncOpenAI
except (ImportError, AttributeError):
    AsyncOpenAI = None

from mobileag.llm.providers.base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class OpenAIProvider(BaseLLMProvider):
    """OpenAI GPT provider (GPT-4.1, GPT-4o, etc.)."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4.1",
        base_url: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(api_key=api_key, model=model, base_url=base_url, **kwargs)
        if AsyncOpenAI is None:
            raise ImportError(
                "The 'openai' package is required to use OpenAIProvider. "
                "Install it via: pip install openai"
            )
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=self.timeout,
        )

    @property
    def name(self) -> str:
        return f"openai ({self.model})"

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Generate a response using the OpenAI chat completions API."""
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
                "OpenAI [%s] responded in %.0fms (%d tokens)",
                self.model, timer.elapsed_ms,
                usage.total_tokens if usage else 0,
            )

            return LLMResponse(
                content=text,
                model=self.model,
                provider="openai",
                prompt_tokens=usage.prompt_tokens if usage else 0,
                completion_tokens=usage.completion_tokens if usage else 0,
                total_tokens=usage.total_tokens if usage else 0,
                latency_ms=timer.elapsed_ms,
                success=True,
            )

        except Exception as exc:
            self._track_request(False)
            logger.error("OpenAI [%s] error: %s", self.model, exc)
            return LLMResponse(
                content="",
                model=self.model,
                provider="openai",
                latency_ms=0,
                success=False,
                error=str(exc),
            )
