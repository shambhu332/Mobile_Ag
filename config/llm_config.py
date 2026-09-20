"""LLM provider configuration and task-to-model routing."""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum, auto

from config.settings import Settings


class TaskType(Enum):
    """Types of analysis tasks that get routed to specific LLMs."""
    MANIFEST_AUDIT = auto()
    CODE_REVIEW = auto()
    API_ANALYSIS = auto()
    NATIVE_ANALYSIS = auto()
    FRIDA_GENERATION = auto()
    POC_GENERATION = auto()
    REPORT_SYNTHESIS = auto()
    CONSENSUS_VOTE = auto()
    SECRET_SCAN = auto()
    DEPENDENCY_SCAN = auto()


@dataclass
class LLMProviderConfig:
    """Configuration for a single LLM provider."""
    name: str
    model: str
    api_key: Optional[str]
    base_url: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.1


@dataclass
class TaskModelMapping:
    """Maps a task to primary and backup LLM providers."""
    primary: list[str] = field(default_factory=list)
    backup: list[str] = field(default_factory=list)


# ── Task-to-provider routing table ──
TASK_ROUTING: dict[TaskType, TaskModelMapping] = {
    TaskType.MANIFEST_AUDIT: TaskModelMapping(
        primary=["gemini_flash"], backup=["grok", "openai"]
    ),
    TaskType.CODE_REVIEW: TaskModelMapping(
        primary=["gemini_pro"], backup=["deepseek", "claude"]
    ),
    TaskType.API_ANALYSIS: TaskModelMapping(
        primary=["openai"], backup=["gemini_pro"]
    ),
    TaskType.NATIVE_ANALYSIS: TaskModelMapping(
        primary=["deepseek"], backup=["openai"]
    ),
    TaskType.FRIDA_GENERATION: TaskModelMapping(
        primary=["gemini_pro"], backup=["openai", "claude"]
    ),
    TaskType.POC_GENERATION: TaskModelMapping(
        primary=["claude"], backup=["gemini_pro"]
    ),
    TaskType.REPORT_SYNTHESIS: TaskModelMapping(
        primary=["claude"], backup=["gemini_pro"]
    ),
    TaskType.CONSENSUS_VOTE: TaskModelMapping(
        primary=["gemini_pro", "openai", "grok"],
        backup=["deepseek", "claude"],
    ),
    TaskType.SECRET_SCAN: TaskModelMapping(
        primary=["gemini_flash"], backup=["openai"]
    ),
    TaskType.DEPENDENCY_SCAN: TaskModelMapping(
        primary=["gemini_flash"], backup=["openai"]
    ),
}


def get_provider_configs(settings: Settings) -> dict[str, LLMProviderConfig]:
    """Build provider configs from available API keys."""
    configs: dict[str, LLMProviderConfig] = {}

    if settings.GEMINI_API_KEY:
        configs["gemini_flash"] = LLMProviderConfig(
            name="gemini_flash",
            model="gemini-2.5-flash",
            api_key=settings.GEMINI_API_KEY,
            max_tokens=8192,
            temperature=0.0,
        )
        configs["gemini_pro"] = LLMProviderConfig(
            name="gemini_pro",
            model="gemini-2.5-pro",
            api_key=settings.GEMINI_API_KEY,
            max_tokens=8192,
            temperature=0.1,
        )

    if settings.OPENAI_API_KEY:
        configs["openai"] = LLMProviderConfig(
            name="openai",
            model="gpt-4.1",
            api_key=settings.OPENAI_API_KEY,
            max_tokens=4096,
            temperature=0.1,
        )

    if settings.DEEPSEEK_API_KEY:
        configs["deepseek"] = LLMProviderConfig(
            name="deepseek",
            model="deepseek-reasoner",
            api_key=settings.DEEPSEEK_API_KEY,
            base_url="https://api.deepseek.com/v1",
            max_tokens=4096,
            temperature=0.2,
        )

    if settings.XAI_API_KEY:
        configs["grok"] = LLMProviderConfig(
            name="grok",
            model="grok-3",
            api_key=settings.XAI_API_KEY,
            base_url="https://api.x.ai/v1",
            max_tokens=4096,
            temperature=0.1,
        )

    if settings.ANTHROPIC_API_KEY:
        configs["claude"] = LLMProviderConfig(
            name="claude",
            model="claude-sonnet-4-20250514",
            api_key=settings.ANTHROPIC_API_KEY,
            max_tokens=4096,
            temperature=0.1,
        )

    return configs


def get_models_for_task(task_type: TaskType) -> TaskModelMapping:
    """Get primary and backup model list for a given task type."""
    return TASK_ROUTING.get(
        task_type,
        TaskModelMapping(primary=["openai"], backup=["gemini_flash"]),
    )
