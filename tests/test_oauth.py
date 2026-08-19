"""Tests for OAuth URL construction and token exchange helpers."""

from __future__ import annotations

import asyncio
import secrets
from unittest.mock import AsyncMock
from urllib.parse import parse_qsl, quote

import httpx
import pytest

from whoop_mcp.exceptions import (
    WhoopClientAuthError,
    WhoopOAuthServerError,
    WhoopRefreshTokenRejected,
)
from whoop_mcp.models import OAuthTokenResponse
from whoop_mcp.oauth import (
    build_authorization_url,
    exchange_authorization_code,
    refresh_access_token,
)
from whoop_mcp.settings import WhoopSettings


def _settings(monkeypatch: pytest.MonkeyPatch, **extra: str) -> WhoopSettings:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "sec")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://app.local/callback")
    for k, v in extra.items():
        monkeypatch.setenv(k, v)
    return WhoopSettings()


def test_build_authorization_url_rejects_short_state(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)
    with pytest.raises(ValueError, match="at least 8 characters"):
        build_authorization_url(settings, state="short")


def test_build_authorization_url_allows_state_longer_than_eight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WHOOP documents a *minimum* of 8 chars; longer values are stronger, not invalid."""

    settings = _settings(monkeypatch)
    state = secrets.token_urlsafe(32)
    url = build_authorization_url(settings, state=state)
    assert quote(state, safe="") in url


def test_refresh_retries_on_5xx_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 502 may mean WHOOP rotated the token without delivering the response."""

    settings = _settings(monkeypatch, WHOOP_TOKEN_RETRY_BACKOFF_SECONDS="0")
    calls: list[int] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(502, text="Bad Gateway")
        return httpx.Response(
            200,
            json={
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "token_type": "bearer",
                "expires_in": 3600,
                "scope": "offline read:sleep",
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    result = asyncio.run(
        refresh_access_token(settings, refresh_token="old", httpx_client=client),
    )
    assert result.access_token == "new-access"
    assert len(calls) == 3


def test_refresh_400_is_terminal_and_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """A dead refresh token is deterministic — retrying only wastes time."""

    settings = _settings(monkeypatch, WHOOP_TOKEN_RETRY_BACKOFF_SECONDS="0")
    calls: list[int] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(400, json={"error": "invalid_grant"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(WhoopRefreshTokenRejected) as exc:
        asyncio.run(refresh_access_token(settings, refresh_token="dead", httpx_client=client))
    assert exc.value.error_code == "invalid_grant"
    assert exc.value.status_code == 400
    assert len(calls) == 1


def test_refresh_401_is_client_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """401 invalid_client is a config bug, not a dead token — must not trigger re-auth."""

    settings = _settings(monkeypatch, WHOOP_TOKEN_RETRY_BACKOFF_SECONDS="0")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(WhoopClientAuthError):
        asyncio.run(refresh_access_token(settings, refresh_token="tok", httpx_client=client))


def test_refresh_exhausts_retries_then_raises_server_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        WHOOP_TOKEN_RETRY_ATTEMPTS="3",
        WHOOP_TOKEN_RETRY_BACKOFF_SECONDS="0",
    )
    calls: list[int] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(502, text="Bad Gateway")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(WhoopOAuthServerError):
        asyncio.run(refresh_access_token(settings, refresh_token="tok", httpx_client=client))
    assert len(calls) == 3


def test_refresh_sends_credentials_in_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """WHOOP clients are registered client_secret_post; Basic auth is rejected."""

    settings = _settings(monkeypatch, WHOOP_TOKEN_RETRY_BACKOFF_SECONDS="0")
    seen: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen.update(dict(parse_qsl(request.content.decode())))
        assert "authorization" not in {k.lower() for k in request.headers}
        return httpx.Response(
            200,
            json={
                "access_token": "a",
                "refresh_token": "r",
                "token_type": "bearer",
                "expires_in": 3600,
                "scope": "offline read:sleep",
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    asyncio.run(refresh_access_token(settings, refresh_token="tok", httpx_client=client))
    assert seen["client_id"] == "cid"
    assert seen["client_secret"] == "sec"
    assert seen["grant_type"] == "refresh_token"
    assert seen["scope"] == "offline"


def test_build_authorization_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "sec")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://app.local/cb?x=1")
    monkeypatch.setenv("WHOOP_DEFAULT_SCOPES", "read:profile offline")

    settings = WhoopSettings()
    url = build_authorization_url(settings, state="abcdefgh")
    assert url.startswith("https://api.prod.whoop.com/oauth/oauth2/auth?")
    assert "response_type=code" in url
    assert "client_id=cid" in url
    assert "state=abcdefgh" in url
    # redirect_uri value must be percent-encoded in the query (e.g. ? and : in the URI)
    assert "redirect_uri=https%3A%2F%2Fapp.local%2Fcb%3Fx%3D1" in url


def test_build_authorization_url_custom_scopes_override_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "sec")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://app.local/callback")
    monkeypatch.setenv(
        "WHOOP_DEFAULT_SCOPES",
        "read:profile offline read:sleep read:recovery",
    )

    settings = WhoopSettings()
    url = build_authorization_url(
        settings,
        state="abcdefgh",
        scopes=["read:workout", "read:body_measurement"],
    )
    assert "read%3Aworkout" in url
    assert "read%3Abody_measurement" in url
    assert "read%3Asleep" not in url
    assert "read%3Aprofile" not in url


@pytest.mark.asyncio
async def test_exchange_authorization_code_parses_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "sec")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://app.local/callback")

    settings = WhoopSettings()
    mock_response = httpx.Response(
        200,
        json={
            "access_token": "at",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "rt",
            "scope": "offline read:profile",
        },
        request=httpx.Request("POST", "https://api.prod.whoop.com/oauth/oauth2/token"),
    )
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post = AsyncMock(return_value=mock_response)

    token = await exchange_authorization_code(settings, code="abc", httpx_client=mock_client)

    assert isinstance(token, OAuthTokenResponse)
    assert token.access_token == "at"
    assert token.refresh_token == "rt"


@pytest.mark.asyncio
async def test_refresh_access_token_parses_json_and_posts_form(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "sec")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://app.local/callback")

    settings = WhoopSettings()
    mock_response = httpx.Response(
        200,
        json={
            "access_token": "at_new",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "rt_new",
            "scope": "offline read:profile",
        },
        request=httpx.Request("POST", str(settings.token_url)),
    )
    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.post = AsyncMock(return_value=mock_response)

    token = await refresh_access_token(
        settings,
        refresh_token="rt_in",
        httpx_client=mock_client,
    )

    assert isinstance(token, OAuthTokenResponse)
    assert token.access_token == "at_new"
    assert token.refresh_token == "rt_new"

    mock_client.post.assert_called_once()
    _args, kwargs = mock_client.post.call_args
    data = kwargs["data"]
    assert data["grant_type"] == "refresh_token"
    assert data["refresh_token"] == "rt_in"
    assert "offline" in data["scope"]
    assert data["client_id"] == "cid"
    assert data["client_secret"] == "sec"
