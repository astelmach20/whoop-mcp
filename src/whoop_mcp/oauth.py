"""WHOOP OAuth 2.0 helpers (authorization code + refresh). Official flow per WHOOP docs."""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any
from urllib.parse import urlencode

import httpx

from whoop_mcp.exceptions import (
    WhoopClientAuthError,
    WhoopOAuthError,
    WhoopOAuthServerError,
    WhoopRefreshTokenRejected,
)
from whoop_mcp.models import OAuthTokenResponse
from whoop_mcp.settings import WhoopSettings

logger = logging.getLogger(__name__)

# WHOOP/ORY Hydra requires `state` to carry at least 8 characters of entropy.
# The OAuth doc page says "must be eight characters long", but WHOOP's own Postman
# tutorial and the underlying fosite error string both say *at least* 8. Treat it
# as a minimum: pinning it to exactly 8 would force callers into weak CSRF values.
MIN_STATE_LENGTH = 8


def build_authorization_url(
    settings: WhoopSettings,
    *,
    state: str,
    scopes: list[str] | None = None,
) -> str:
    """Build the user-facing authorization URL (step 1 of the authorization code grant)."""

    if len(state) < MIN_STATE_LENGTH:
        msg = (
            f"WHOOP requires `state` to be at least {MIN_STATE_LENGTH} characters "
            "for sufficient CSRF entropy; prefer secrets.token_urlsafe(32)."
        )
        raise ValueError(msg)

    scope_list = scopes if scopes is not None else settings.scope_list()
    query = {
        "response_type": "code",
        "client_id": settings.client_id,
        "redirect_uri": str(settings.redirect_uri),
        "scope": " ".join(scope_list),
        "state": state,
    }
    base = str(settings.authorization_url).rstrip("/")
    return f"{base}?{urlencode(query)}"


async def exchange_authorization_code(
    settings: WhoopSettings,
    *,
    code: str,
    httpx_client: httpx.AsyncClient | None = None,
) -> OAuthTokenResponse:
    """Exchange an authorization code for tokens at the WHOOP token URL."""

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": settings.client_id,
        "client_secret": settings.client_secret.get_secret_value(),
        "redirect_uri": str(settings.redirect_uri),
    }
    return await _post_token(settings, data, httpx_client)


async def refresh_access_token(
    settings: WhoopSettings,
    *,
    refresh_token: str,
    httpx_client: httpx.AsyncClient | None = None,
) -> OAuthTokenResponse:
    """Refresh tokens; requires prior `offline` scope during authorization.

    WHOOP rotates refresh tokens: the response refresh token replaces the prior one,
    and the previous one is invalidated immediately with no overlap window. Callers
    MUST persist the response before doing anything else that could fail.
    """

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": settings.client_id,
        "client_secret": settings.client_secret.get_secret_value(),
        # WHOOP explicitly recommends re-sending `offline` on refresh so the new
        # token remains refreshable. Their documented sample response echoes back
        # the full original scope set, so this does not narrow the grant.
        "scope": "offline",
    }
    response = await _post_token(settings, data, httpx_client)

    granted = set((response.scope or "").split())
    if granted and "offline" not in granted:
        logger.warning(
            "WHOOP refresh response did not include the `offline` scope (got %r); "
            "the new token may not be refreshable.",
            response.scope,
        )
    return response


def _oauth_token_response_from_json(payload: dict[str, object]) -> OAuthTokenResponse:
    try:
        return OAuthTokenResponse.model_validate(payload)
    except Exception as e:
        raise WhoopOAuthError(
            "Token endpoint returned JSON that does not match the expected OAuth token shape.",
            response_text=str(payload),
        ) from e


def _error_code(response: httpx.Response) -> str | None:
    """Extract the RFC 6749 `error` field from a token endpoint error body."""

    try:
        body: Any = response.json()
    except Exception:
        return None
    if isinstance(body, dict):
        code = body.get("error")
        if isinstance(code, str):
            return code
    return None


def _classify_token_error(response: httpx.Response) -> WhoopOAuthError:
    """Map a token endpoint error response onto a specific exception type.

    WHOOP (ORY Hydra) returns 400 for a dead refresh token and 401 for bad client
    credentials. Collapsing those loses the only signal that distinguishes
    "user must re-authorize" from "our config is wrong".
    """

    status = response.status_code
    code = _error_code(response)
    text = response.text

    if status >= 500:
        return WhoopOAuthServerError(
            f"Token endpoint HTTP {status} (server-side; refresh outcome indeterminate)",
            status_code=status,
            response_text=text,
            error_code=code,
        )
    if status == 401 or code == "invalid_client":
        return WhoopClientAuthError(
            f"Token endpoint HTTP {status}: client authentication failed ({code}). "
            "Check WHOOP_CLIENT_ID/WHOOP_CLIENT_SECRET; WHOOP clients are registered "
            "`client_secret_post`, so credentials must go in the request body.",
            status_code=status,
            response_text=text,
            error_code=code,
        )
    if status == 400:
        return WhoopRefreshTokenRejected(
            f"Token endpoint HTTP {status}: grant rejected ({code}). The refresh token "
            "is no longer valid — re-authorize with `whoop-mcp login`.",
            status_code=status,
            response_text=text,
            error_code=code,
        )
    return WhoopOAuthError(
        f"Token endpoint HTTP {status}",
        status_code=status,
        response_text=text,
        error_code=code,
    )


async def _post_token(
    settings: WhoopSettings,
    data: dict[str, str],
    httpx_client: httpx.AsyncClient | None,
) -> OAuthTokenResponse:
    """POST to the token endpoint, retrying transient server/transport failures.

    Retries only apply to 5xx and transport errors. A 5xx is the dangerous case:
    WHOOP may have already rotated the refresh token before failing to deliver the
    response, which permanently desyncs us. Retrying immediately is the only chance
    to recover, so it is worth several attempts before surfacing the failure.
    4xx responses are deterministic and are never retried.
    """

    client_owned = httpx_client is None
    client = httpx_client or httpx.AsyncClient(timeout=settings.http_timeout_seconds)
    attempts = max(1, settings.token_retry_attempts)
    last_error: Exception | None = None
    try:
        for attempt in range(1, attempts + 1):
            try:
                response = await client.post(
                    str(settings.token_url),
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except httpx.HTTPError as e:
                last_error = WhoopOAuthServerError(
                    f"Token endpoint transport failure: {e!r} (refresh outcome indeterminate)",
                )
            else:
                if not response.is_error:
                    return _oauth_token_response_from_json(response.json())
                error = _classify_token_error(response)
                if not error.is_retryable:
                    raise error
                last_error = error

            if attempt < attempts:
                backoff = settings.token_retry_backoff_seconds * (2 ** (attempt - 1))
                # Jitter so concurrent clients do not retry in lockstep.
                delay = backoff * (1.0 + random.random() * 0.25)  # noqa: S311
                logger.warning(
                    "WHOOP token request failed (attempt %d/%d): %s — retrying in %.1fs",
                    attempt,
                    attempts,
                    last_error,
                    delay,
                )
                await asyncio.sleep(delay)

        assert last_error is not None
        raise last_error
    finally:
        if client_owned:
            await client.aclose()
