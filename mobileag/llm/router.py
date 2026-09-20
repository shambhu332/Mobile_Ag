"""Intelligent LLM routing engine — routes tasks to the best available provider."""

import logging
from typing import Optional

from config.llm_config import (
    TaskType,
    LLMProviderConfig,
    get_provider_configs,
    get_models_for_task,
)
from config.settings import Settings
from mobileag.llm.providers.base import BaseLLMProvider, LLMResponse
from mobileag.llm.providers.gemini import GeminiProvider
from mobileag.llm.providers.openai_gpt import OpenAIProvider
from mobileag.llm.providers.deepseek import DeepSeekProvider
from mobileag.llm.providers.grok import GrokProvider
from mobileag.llm.providers.claude import ClaudeProvider

logger = logging.getLogger(__name__)

# Maps config name → provider class
_PROVIDER_CLASSES: dict[str, type[BaseLLMProvider]] = {
    "gemini_flash": GeminiProvider,
    "gemini_pro": GeminiProvider,
    "openai": OpenAIProvider,
    "deepseek": DeepSeekProvider,
    "grok": GrokProvider,
    "claude": ClaudeProvider,
}


class LLMRouter:
    """Routes analysis tasks to the best available LLM provider.

    Features:
    - Task-aware routing (code review → Gemini Pro, reports → Claude, etc.)
    - Automatic fallback to backup providers on failure
    - Provider health tracking
    - Configurable retry logic
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        self._providers: dict[str, BaseLLMProvider] = {}
        self._initialize_providers()

    def _initialize_providers(self) -> None:
        """Build provider instances from available API keys."""
        configs = get_provider_configs(self._settings)

        for config_name, config in configs.items():
            provider_cls = _PROVIDER_CLASSES.get(config_name)
            if provider_cls and config.api_key:
                try:
                    self._providers[config_name] = provider_cls(
                        api_key=config.api_key,
                        model=config.model,
                        base_url=config.base_url,
                        max_tokens=config.max_tokens,
                    )
                    logger.info("Initialized provider: %s (%s)", config_name, config.model)
                except Exception as e:
                    logger.warning("Failed to init provider %s: %s", config_name, e)

        if not self._providers:
            logger.error("No LLM providers available! Set at least one API key in .env")

    def get_available_providers(self) -> list[str]:
        """Return names of all initialized providers."""
        return list(self._providers.keys())

    def get_provider(self, name: str) -> Optional[BaseLLMProvider]:
        """Get a specific provider by name."""
        return self._providers.get(name)

    def _select_providers_for_task(self, task_type: TaskType) -> list[BaseLLMProvider]:
        """Select ordered list of providers for a task (primary first, then backups)."""
        mapping = get_models_for_task(task_type)
        ordered: list[BaseLLMProvider] = []

        # Add primary providers first
        for name in mapping.primary:
            if name in self._providers:
                ordered.append(self._providers[name])

        # Then backup providers
        for name in mapping.backup:
            if name in self._providers and self._providers[name] not in ordered:
                ordered.append(self._providers[name])

        # If none matched, try any available provider
        if not ordered:
            ordered = list(self._providers.values())

        return ordered

    async def route(
        self,
        task_type: TaskType,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Route a task to the best available provider with automatic fallback.

        Args:
            task_type: Type of analysis task (determines provider selection).
            system_prompt: System-level instructions.
            user_prompt: The analysis prompt with code/data.
            temperature: Sampling temperature.
            max_tokens: Max response tokens.

        Returns:
            LLMResponse from the first successful provider.
        """
        providers = self._select_providers_for_task(task_type)

        if not providers:
            return LLMResponse.from_error(
                "router", "none", "No LLM providers available for this task"
            )

        last_error = ""
        for provider in providers:
            logger.info(
                "Routing %s to %s",
                task_type.name,
                provider.name,
            )

            response = await provider.generate(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            if response.success:
                return response

            last_error = response.error or "Unknown error"
            logger.warning(
                "Provider %s failed for %s: %s — trying next",
                provider.name,
                task_type.name,
                last_error,
            )

        return LLMResponse.from_error(
            "router",
            "all_failed",
            f"All providers failed. Last error: {last_error}",
        )

    async def route_to_multiple(
        self,
        task_type: TaskType,
        system_prompt: str,
        user_prompt: str,
        count: int = 3,
        temperature: float = 0.1,
    ) -> list[LLMResponse]:
        """Send the same prompt to multiple providers (for consensus voting).

        Args:
            task_type: Task type.
            system_prompt: System instructions.
            user_prompt: Analysis prompt.
            count: Number of providers to query.
            temperature: Sampling temperature.

        Returns:
            List of LLMResponses from different providers.
        """
        import asyncio

        providers = self._select_providers_for_task(task_type)[:count]

        if not providers:
            return [LLMResponse.from_error("router", "none", "No providers available")]

        tasks = [
            provider.generate(system_prompt, user_prompt, temperature)
            for provider in providers
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        responses: list[LLMResponse] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                responses.append(
                    LLMResponse.from_error(
                        providers[i].name,
                        providers[i].model,
                        str(result),
                    )
                )
            else:
                responses.append(result)

        return responses
