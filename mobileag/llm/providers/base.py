"""Abstract base class for all LLM providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
import time
import logging

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider."""
    content: str
    model: str
    provider: str
    tokens_used: int = 0
    latency_ms: float = 0.0
    error: Optional[str] = None
    success: bool = True

    @staticmethod
    def from_error(provider: str, model: str, error: str) -> "LLMResponse":
        """Create an error response."""
        return LLMResponse(
            content="",
            model=model,
            provider=provider,
            error=error,
            success=False,
        )


class BaseLLMProvider(ABC):
    """Abstract base class that all LLM providers must implement.

    Each provider wraps a specific LLM API (Gemini, OpenAI, etc.)
    and normalizes the response into a standard LLMResponse object.
    """

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
        max_tokens: int = 4096,
        timeout: float = 60.0,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._request_count = 0
        self._error_count = 0

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name."""
        ...

    @abstractmethod
    async def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Send a prompt to the LLM and return a standardized response.

        Args:
            system_prompt: System-level instructions for the LLM.
            user_prompt: The actual analysis prompt with code/data.
            temperature: Sampling temperature (0.0 = deterministic).
            max_tokens: Max response tokens (None = use provider default).

        Returns:
            LLMResponse with the generated text or error details.
        """
        ...

    def is_available(self) -> bool:
        """Check if this provider has a valid API key configured."""
        return bool(self.api_key and self.api_key.strip())

    @property
    def health_score(self) -> float:
        """Provider reliability score based on recent request history."""
        if self._request_count == 0:
            return 1.0
        return 1.0 - (self._error_count / self._request_count)

    def _track_request(self, success: bool) -> None:
        """Track request outcomes for health scoring."""
        self._request_count += 1
        if not success:
            self._error_count += 1

    def _measure_time(self) -> "_Timer":
        """Context manager to measure request latency."""
        return _Timer()


class _Timer:
    """Simple latency timer."""

    def __init__(self):
        self.start_time = 0.0
        self.elapsed_ms = 0.0

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.elapsed_ms = (time.perf_counter() - self.start_time) * 1000
