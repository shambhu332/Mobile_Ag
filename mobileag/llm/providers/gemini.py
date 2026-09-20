"""Google Gemini LLM provider using the google-genai SDK."""

import logging
from typing import Optional

try:
    from google import genai
    from google.genai import types
except (ImportError, AttributeError):
    genai = None
    types = None

from mobileag.llm.providers.base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class GeminiProvider(BaseLLMProvider):
    """Google Gemini provider (supports Flash and Pro models)."""

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.5-flash",
        **kwargs,
    ):
        super().__init__(api_key=api_key, model=model, **kwargs)
        if genai is None:
            raise ImportError(
                "The 'google-genai' package is required to use GeminiProvider. "
                "Install it via: pip install google-genai"
            )
        self._client = genai.Client(api_key=api_key)

    @property
    def name(self) -> str:
        return f"gemini ({self.model})"

    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Generate a response using the Gemini API."""
        tokens = max_tokens or self.max_tokens

        try:
            with self._measure_time() as timer:
                response = self._client.models.generate_content(
                    model=self.model,
                    contents=user_prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        temperature=temperature,
                        max_output_tokens=tokens,
                    ),
                )

            text = response.text or ""
            usage = getattr(response, "usage_metadata", None)
            total_tokens = (
                usage.total_token_count if usage else 0
            )

            self._track_request(True)
            logger.info(
                "Gemini [%s] responded in %.0fms (%d tokens)",
                self.model, timer.elapsed_ms, total_tokens,
            )

            return LLMResponse(
                content=text,
                model=self.model,
                provider="gemini",
                prompt_tokens=getattr(usage, "prompt_token_count", 0) if usage else 0,
                completion_tokens=getattr(usage, "candidates_token_count", 0) if usage else 0,
                total_tokens=total_tokens,
                latency_ms=timer.elapsed_ms,
                success=True,
            )

        except Exception as exc:
            self._track_request(False)
            logger.error("Gemini [%s] error: %s", self.model, exc)
            return LLMResponse(
                content="",
                model=self.model,
                provider="gemini",
                latency_ms=0,
                success=False,
                error=str(exc),
            )
