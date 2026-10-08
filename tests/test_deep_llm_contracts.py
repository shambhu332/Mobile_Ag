"""Provider success-contract tests using synthetic SDK objects only."""
import importlib
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from mobileag.llm.providers.base import BaseLLMProvider, LLMResponse


def test_llm_usage_contract_accepts_provider_accounting():
    response = LLMResponse(content='Synthetic', model='Synthetic', provider='Synthetic',
                           prompt_tokens=7, completion_tokens=3, total_tokens=10)
    assert response.success is True
    assert response.tokens_used == 10
    assert response.prompt_tokens == 7
    assert response.completion_tokens == 3
    assert response.total_tokens == 10


@pytest.mark.asyncio
@pytest.mark.parametrize('module_name,class_name', [
    ('openai_gpt', 'OpenAIProvider'), ('deepseek', 'DeepSeekProvider'), ('grok', 'GrokProvider'),
])
async def test_openai_compatible_success_not_discarded(module_name, class_name):
    module = importlib.import_module('mobileag.llm.providers.' + module_name)
    provider = object.__new__(getattr(module, class_name))
    BaseLLMProvider.__init__(provider, api_key='synthetic-key', model='synthetic-model')
    create = AsyncMock(return_value=SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='Synthetic advice'))],
        usage=SimpleNamespace(prompt_tokens=7, completion_tokens=3, total_tokens=10),
    ))
    provider._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    response = await provider.generate('Synthetic system', 'Synthetic user')
    assert response.success is True
    assert response.content == 'Synthetic advice'
    assert response.tokens_used == 10
    create.assert_awaited_once()


@pytest.mark.asyncio
async def test_claude_success_not_discarded():
    from mobileag.llm.providers.claude import ClaudeProvider
    provider = object.__new__(ClaudeProvider)
    BaseLLMProvider.__init__(provider, api_key='synthetic-key', model='synthetic-model')
    create = AsyncMock(return_value=SimpleNamespace(
        content=[SimpleNamespace(text='Synthetic advice')],
        usage=SimpleNamespace(input_tokens=7, output_tokens=3),
    ))
    provider._client = SimpleNamespace(messages=SimpleNamespace(create=create))
    response = await provider.generate('Synthetic system', 'Synthetic user')
    assert response.success is True
    assert response.tokens_used == 10
    create.assert_awaited_once()
