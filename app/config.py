"""Application settings, read from environment variables and an optional `.env` file.

Every tunable lives here so the rest of the code never touches `os.environ`.
Environment variables take precedence over `.env`; see `.env.example`.
"""

from __future__ import annotations

import logging
from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration of the assistant."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # LLM endpoint: any OpenAI-compatible API (default: Groq).
    llm_base_url: str = "https://api.groq.com/openai/v1"
    llm_api_key: SecretStr = SecretStr("")
    llm_model: str = "openai/gpt-oss-20b"
    llm_timeout_s: float = Field(default=60.0, gt=0)
    llm_max_retries: int = Field(
        default=3, ge=0, description="Retries on HTTP 429 / 5xx / connection errors."
    )
    llm_retry_base_s: float = Field(default=2.0, ge=0, description="First back-off delay.")

    # Agent loop
    max_steps: int = Field(default=6, ge=1, description="Max LLM round-trips per question.")

    # Per-IP rate limit on /ask, protects a shared LLM quota on public demos (0 = no limit).
    rate_limit_per_hour: int = Field(default=30, ge=0)
    # Behind a reverse proxy (e.g. Render) the client address is read from X-Forwarded-For.
    trust_forwarded_for: bool = False

    log_level: str = "INFO"

    @property
    def llm_configured(self) -> bool:
        return bool(self.llm_api_key.get_secret_value())


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings (loaded once)."""
    return Settings()


def configure_logging(level: str = "INFO") -> None:
    """Set up console logging for the application and its scripts."""
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
