"""Provider adapters: SDKs are imported only for explicitly approved execution."""
from importlib import import_module
from .base import BaseLLMProvider, LLMResponse
_MODULES={'GeminiProvider':'gemini','OpenAIProvider':'openai_gpt','DeepSeekProvider':'deepseek','GrokProvider':'grok','ClaudeProvider':'claude'}
__all__=['BaseLLMProvider','LLMResponse',*_MODULES]
def __getattr__(name):
    if name not in _MODULES:raise AttributeError(name)
    value=getattr(import_module('.'+_MODULES[name],__name__),name)
    globals()[name]=value
    return value
