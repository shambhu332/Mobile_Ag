import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from mobileag.llm.router import LLMRouter
from config.settings import Settings
from config.llm_config import TaskType
from mobileag.llm.providers.base import LLMResponse, BaseLLMProvider


@pytest.fixture
def mock_settings():
    """Provide a settings object with dummy API keys."""
    return Settings(
        GEMINI_API_KEY="dummy_gemini_key",
        OPENAI_API_KEY="dummy_openai_key",
        DEEPSEEK_API_KEY=None,
        XAI_API_KEY=None,
        ANTHROPIC_API_KEY=None,
    )


@pytest.mark.asyncio
async def test_router_initialization(mock_settings):
    """Test that the router initializes only providers with keys and installed packages."""
    mock_gemini_cls = MagicMock(spec=BaseLLMProvider)
    mock_openai_cls = MagicMock(spec=BaseLLMProvider)

    with patch.dict(
        "mobileag.llm.router._PROVIDER_CLASSES",
        {
            "gemini_flash": mock_gemini_cls,
            "gemini_pro": mock_gemini_cls,
            "openai": mock_openai_cls,
        },
    ):
        router = LLMRouter(mock_settings)
        providers = router.get_available_providers()

        assert "openai" in providers
        assert "gemini_pro" in providers
        assert "gemini_flash" in providers
        assert "claude" not in providers
        assert "grok" not in providers


@pytest.mark.asyncio
async def test_router_routing(mock_settings):
    """Test task-based routing logic."""
    router = LLMRouter(mock_settings)

    # Mock the OpenAI provider's generate method
    provider = router.get_provider("openai")
    assert provider is not None
    provider.generate = AsyncMock(
        return_value=LLMResponse(
            content="Mocked response", model="gpt-4.1", provider="openai", success=True
        )
    )

    # API_ANALYSIS task routes to openai primarily
    response = await router.route(
        task_type=TaskType.API_ANALYSIS,
        system_prompt="sys",
        user_prompt="user",
    )

    assert response.success is True
    assert response.content == "Mocked response"
    assert response.provider == "openai"
    provider.generate.assert_called_once()
