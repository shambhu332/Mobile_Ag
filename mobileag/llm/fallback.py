"""Automatic retry and fallback handler for LLM provider failures."""

import asyncio
import logging
from typing import Optional

from mobileag.llm.providers.base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class FallbackHandler:
    """Wraps LLM calls with exponential backoff and provider failover.

    Tracks per-provider health metrics and automatically skips
    consistently failing providers.
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        health_threshold: float = 0.3,
    ):
        self._max_retries = max_retries
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._health_threshold = health_threshold
        self._provider_stats: dict[str, dict] = {}

    def _get_stats(self, provider_name: str) -> dict:
        """Get or create stats tracker for a provider."""
        if provider_name not in self._provider_stats:
            self._provider_stats[provider_name] = {
                "total": 0,
                "failures": 0,
                "consecutive_failures": 0,
            }
        return self._provider_stats[provider_name]

    def _record_success(self, provider_name: str) -> None:
        """Record a successful request."""
        stats = self._get_stats(provider_name)
        stats["total"] += 1
        stats["consecutive_failures"] = 0

    def _record_failure(self, provider_name: str) -> None:
        """Record a failed request."""
        stats = self._get_stats(provider_name)
        stats["total"] += 1
        stats["failures"] += 1
        stats["consecutive_failures"] += 1

    def is_healthy(self, provider_name: str) -> bool:
        """Check if a provider is considered healthy enough to use."""
        stats = self._get_stats(provider_name)
        if stats["total"] == 0:
            return True
        if stats["consecutive_failures"] >= 5:
            return False
        success_rate = 1.0 - (stats["failures"] / stats["total"])
        return success_rate >= self._health_threshold

    def get_health_report(self) -> dict[str, dict]:
        """Return health stats for all tracked providers."""
        return dict(self._provider_stats)

    async def call_with_retry(
        self,
        provider: BaseLLMProvider,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Call a single provider with exponential backoff retry.

        Args:
            provider: The LLM provider to call.
            system_prompt: System instructions.
            user_prompt: Analysis prompt.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.

        Returns:
            LLMResponse — successful response or final error after retries.
        """
        if not self.is_healthy(provider.name):
            return LLMResponse.from_error(
                provider.name,
                provider.model,
                f"Provider {provider.name} is unhealthy (too many recent failures)",
            )

        last_error = ""
        for attempt in range(self._max_retries):
            response = await provider.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            if response.success:
                self._record_success(provider.name)
                return response

            last_error = response.error or "Unknown error"
            self._record_failure(provider.name)

            if attempt < self._max_retries - 1:
                delay = min(
                    self._base_delay * (2 ** attempt),
                    self._max_delay,
                )
                logger.warning(
                    "Retry %d/%d for %s in %.1fs: %s",
                    attempt + 1,
                    self._max_retries,
                    provider.name,
                    delay,
                    last_error,
                )
                await asyncio.sleep(delay)

        return LLMResponse.from_error(
            provider.name,
            provider.model,
            f"All {self._max_retries} retries failed. Last: {last_error}",
        )

    async def call_with_fallback(
        self,
        providers: list[BaseLLMProvider],
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Try multiple providers in order until one succeeds.

        Args:
            providers: Ordered list of providers to try.
            system_prompt: System instructions.
            user_prompt: Analysis prompt.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.

        Returns:
            LLMResponse from the first successful provider.
        """
        if not providers:
            return LLMResponse.from_error(
                "fallback", "none", "No providers given"
            )

        # Filter to healthy providers first
        healthy = [p for p in providers if self.is_healthy(p.name)]
        if not healthy:
            logger.warning("No healthy providers — trying all anyway")
            healthy = providers

        last_error = ""
        for provider in healthy:
            response = await self.call_with_retry(
                provider=provider,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            if response.success:
                return response

            last_error = response.error or "Unknown error"
            logger.warning(
                "Provider %s exhausted retries, trying next. Error: %s",
                provider.name,
                last_error,
            )

        return LLMResponse.from_error(
            "fallback",
            "all_exhausted",
            f"All providers exhausted. Last: {last_error}",
        )
