"""Central configuration loaded from environment variables."""

import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """MobileAg platform configuration."""

    # ── LLM API Keys (all optional — works with minimum 1) ──
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    DEEPSEEK_API_KEY: Optional[str] = None
    XAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None

    # ── Database Configuration ──
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    POSTGRES_URI: str = "postgresql://user:pass@localhost:5432/mobileag"

    # ── External Tool Paths ──
    JADX_PATH: str = "/usr/local/bin/jadx"
    APKTOOL_PATH: str = "/usr/local/bin/apktool"
    GHIDRA_PATH: str = "/opt/ghidra"

    # ── Output ──
    OUTPUT_DIR: str = "./output"

    # ── Analysis Thresholds ──
    confidence_threshold: float = 0.6
    max_llm_retries: int = 3
    consensus_min_votes: int = 2
    entropy_threshold: float = 4.5

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @property
    def enabled_providers(self) -> list[str]:
        """Return list of LLM providers that have API keys configured."""
        providers = []
        if self.GEMINI_API_KEY:
            providers.append("gemini")
        if self.OPENAI_API_KEY:
            providers.append("openai")
        if self.DEEPSEEK_API_KEY:
            providers.append("deepseek")
        if self.XAI_API_KEY:
            providers.append("grok")
        if self.ANTHROPIC_API_KEY:
            providers.append("claude")
        return providers


def get_settings() -> Settings:
    """Factory function to create settings instance."""
    return Settings()
