"""Application settings aligned with WHOOP OAuth 2.0 and Developer API documentation."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AnyUrl, Field, HttpUrl, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class WhoopSettings(BaseSettings):
    """WHOOP OAuth client and API configuration.

    Official references:
    - OAuth: https://developer.whoop.com/docs/developing/oauth
    - API: https://developer.whoop.com/api
    """

    model_config = SettingsConfigDict(
        env_prefix="WHOOP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    client_id: str = Field(description="Client ID from the WHOOP Developer Dashboard.")
    client_secret: SecretStr = Field(
        description="Client secret from the WHOOP Developer Dashboard.",
    )
    redirect_uri: AnyUrl = Field(
        description="Registered redirect (callback) URI; must match the dashboard registration.",
    )

    authorization_url: HttpUrl = Field(
        default="https://api.prod.whoop.com/oauth/oauth2/auth",
        description="WHOOP authorization endpoint (authorization code flow).",
    )
    token_url: HttpUrl = Field(
        default="https://api.prod.whoop.com/oauth/oauth2/token",
        description="WHOOP token endpoint (code exchange and refresh).",
    )
    api_base_url: HttpUrl = Field(
        default="https://api.prod.whoop.com/developer",
        description="Base URL for WHOOP Developer API resources (Bearer access token).",
    )

    default_scopes: str = Field(
        default=(
            "offline read:profile read:cycles read:sleep read:recovery "
            "read:workout read:body_measurement"
        ),
        description="Space-separated OAuth scopes (include `offline` for refresh tokens).",
    )

    http_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)
    token_refresh_skew_seconds: float = Field(
        default=60.0,
        ge=0.0,
        le=600.0,
        description="Refresh access tokens this many seconds before computed expiry.",
    )
    token_retry_attempts: int = Field(
        default=4,
        ge=1,
        le=10,
        description=(
            "Attempts for a token endpoint request. Only 5xx/transport failures are "
            "retried; a 5xx may mean WHOOP rotated the refresh token without "
            "delivering the response, which is unrecoverable, so retry generously."
        ),
    )
    token_retry_backoff_seconds: float = Field(
        default=1.5,
        ge=0.0,
        le=30.0,
        description="Base for exponential backoff between token endpoint retries.",
    )
    token_store_path: str = Field(
        default_factory=lambda: str(Path.home() / ".config" / "whoop-mcp" / "tokens.json"),
        description="Path for persisted OAuth tokens (JSON). Override with WHOOP_TOKEN_STORE_PATH.",
    )

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    def scope_list(self) -> list[str]:
        return [s for s in self.default_scopes.split() if s]


@lru_cache
def get_settings() -> WhoopSettings:
    """Cached settings instance for process lifetime."""

    return WhoopSettings()
