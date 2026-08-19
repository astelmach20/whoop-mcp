"""WHOOP Developer API MCP server (stdio) built with FastMCP."""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from whoop_mcp import __version__
from whoop_mcp.api_client import WhoopApiClient
from whoop_mcp.exceptions import TokenStoreError
from whoop_mcp.models import PaginatedListParams
from whoop_mcp.settings import WhoopSettings, get_settings
from whoop_mcp.token_store import FileTokenStore

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="whoop-mcp",
    instructions=(
        "Bridge to the WHOOP Developer API v2. "
        "First run `uv run whoop-mcp login` to store OAuth tokens, then use the data tools. "
        "Docs: https://developer.whoop.com/docs/developing/oauth"
    ),
)


CONNECT_INSTRUCTIONS_TEXT = """## Connect WHOOP (one-time OAuth)

1. Register an app in the WHOOP Developer Dashboard and copy the **Client ID** and
   **Client secret**.
2. Add a **Redirect URI** for local login, e.g. `http://127.0.0.1:8780/callback`
   (must match `WHOOP_REDIRECT_URI` exactly).
3. Set environment variables (or a `.env` file): `WHOOP_CLIENT_ID`,
   `WHOOP_CLIENT_SECRET`, `WHOOP_REDIRECT_URI`.
4. Run **`uv run whoop-mcp login`** and finish sign-in in the browser.
5. Run the MCP server with **`uv run whoop-mcp`** (stdio). Tokens use
   `WHOOP_TOKEN_STORE_PATH` (default: `~/.config/whoop-mcp/tokens.json`).

Include the `offline` scope (see `WHOOP_DEFAULT_SCOPES`) so tokens can refresh."""


@asynccontextmanager
async def _whoop_client() -> AsyncIterator[WhoopApiClient]:
    settings = get_settings()
    store = FileTokenStore(Path(settings.token_store_path))
    bundle = store.load()
    if bundle is None:
        raise TokenStoreError(
            "No OAuth tokens on disk. Run `uv run whoop-mcp login` once, then restart the "
            "MCP server.",
            path=settings.token_store_path,
        )
    client = WhoopApiClient(settings, token_bundle=bundle, token_store=store)
    try:
        yield client
    finally:
        await client.aclose()


@mcp.tool()
async def server_ping() -> str:
    """Return a static string to verify the MCP server process is running."""

    return "whoop-mcp: ok"


@mcp.tool()
async def connect_instructions() -> str:
    """Show how to configure env vars and run the separate `whoop-mcp login` flow."""

    return CONNECT_INSTRUCTIONS_TEXT


@mcp.tool()
async def auth_status() -> dict[str, Any]:
    """Report whether a token file exists and basic metadata (no network calls)."""

    settings = get_settings()
    store = FileTokenStore(Path(settings.token_store_path))
    bundle = store.load()
    if bundle is None:
        return {
            "authenticated": False,
            "token_path": settings.token_store_path,
            "detail": "No token file; run `uv run whoop-mcp login`.",
        }
    exp = bundle.access_token_expires_at
    now = datetime.now(UTC)
    expired = exp is not None and now >= exp
    expires_in = int((exp - now).total_seconds()) if exp is not None else None

    # `authenticated` must reflect whether the credentials actually work, not merely
    # whether a token file exists on disk. Reporting True for a long-expired token
    # sends callers chasing phantom API errors.
    result: dict[str, Any] = {
        "authenticated": not expired,
        "token_path": settings.token_store_path,
        "access_token_expires_at": exp.isoformat() if exp else None,
        "access_token_expired": expired,
        "expires_in_seconds": expires_in,
        "has_refresh_token": bundle.refresh_token is not None,
        "scope": bundle.scope,
    }
    if expired:
        result["detail"] = (
            f"Access token expired at {exp.isoformat()}. If the refresh loop cannot "
            "recover it, the refresh token was likely invalidated (WHOOP rotates "
            "refresh tokens with no overlap window) — re-run `whoop-mcp login`."
        )
    elif exp is None:
        result["detail"] = "No recorded expiry; token validity is unknown."
    return result


@mcp.tool()
async def get_profile() -> dict[str, Any]:
    """GET /v2/user/profile/basic — name and email."""

    async with _whoop_client() as client:
        data = await client.get_user_profile_basic()
    return data.model_dump(mode="json")


@mcp.tool()
async def get_body_measurements() -> dict[str, Any]:
    """GET /v2/user/measurement/body — height, weight, max heart rate."""

    async with _whoop_client() as client:
        data = await client.get_user_body_measurement()
    return data.model_dump(mode="json")


@mcp.tool()
async def list_cycles(
    limit: int | None = None,
    start: str | None = None,
    end: str | None = None,
    next_token: str | None = None,
) -> dict[str, Any]:
    """GET /v2/cycle — physiological cycles (paginated, max 25 per page)."""

    q = PaginatedListParams(limit=limit, start=start, end=end, next_token=next_token)
    async with _whoop_client() as client:
        data = await client.list_cycles(q)
    return data.model_dump(mode="json")


@mcp.tool()
async def get_cycle(cycle_id: int) -> dict[str, Any]:
    """GET /v2/cycle/{cycleId} — single cycle by ID."""

    async with _whoop_client() as client:
        data = await client.get_cycle(cycle_id)
    return data.model_dump(mode="json")


@mcp.tool()
async def list_recovery(
    limit: int | None = None,
    start: str | None = None,
    end: str | None = None,
    next_token: str | None = None,
) -> dict[str, Any]:
    """GET /v2/recovery — recovery collection (paginated)."""

    q = PaginatedListParams(limit=limit, start=start, end=end, next_token=next_token)
    async with _whoop_client() as client:
        data = await client.list_recovery(q)
    return data.model_dump(mode="json")


@mcp.tool()
async def get_latest_recovery() -> dict[str, Any]:
    """Convenience: latest recovery row (`limit=1` on the recovery collection)."""

    async with _whoop_client() as client:
        data = await client.list_recovery(PaginatedListParams(limit=1))
    return data.model_dump(mode="json")


@mcp.tool()
async def get_recovery_for_cycle(cycle_id: int) -> dict[str, Any]:
    """GET /v2/cycle/{cycleId}/recovery — recovery for a specific cycle."""

    async with _whoop_client() as client:
        data = await client.get_recovery_for_cycle(cycle_id)
    return data.model_dump(mode="json")


@mcp.tool()
async def list_sleep(
    limit: int | None = None,
    start: str | None = None,
    end: str | None = None,
    next_token: str | None = None,
) -> dict[str, Any]:
    """GET /v2/activity/sleep — sleep records (paginated)."""

    q = PaginatedListParams(limit=limit, start=start, end=end, next_token=next_token)
    async with _whoop_client() as client:
        data = await client.list_sleep(q)
    return data.model_dump(mode="json")


@mcp.tool()
async def get_sleep(sleep_id: str) -> dict[str, Any]:
    """GET /v2/activity/sleep/{sleepId} — single sleep by UUID."""

    async with _whoop_client() as client:
        data = await client.get_sleep(sleep_id)
    return data.model_dump(mode="json")


@mcp.tool()
async def get_sleep_for_cycle(cycle_id: int) -> dict[str, Any]:
    """GET /v2/cycle/{cycleId}/sleep — sleep associated with a cycle."""

    async with _whoop_client() as client:
        data = await client.get_sleep_for_cycle(cycle_id)
    return data.model_dump(mode="json")


@mcp.tool()
async def list_workouts(
    limit: int | None = None,
    start: str | None = None,
    end: str | None = None,
    next_token: str | None = None,
) -> dict[str, Any]:
    """GET /v2/activity/workout — workouts (paginated)."""

    q = PaginatedListParams(limit=limit, start=start, end=end, next_token=next_token)
    async with _whoop_client() as client:
        data = await client.list_workouts(q)
    return data.model_dump(mode="json")


@mcp.tool()
async def get_workout(workout_id: str) -> dict[str, Any]:
    """GET /v2/activity/workout/{workoutId} — single workout by UUID."""

    async with _whoop_client() as client:
        data = await client.get_workout(workout_id)
    return data.model_dump(mode="json")


@mcp.tool()
async def whoop_health_summary() -> dict[str, Any]:
    """Concise snapshot: profile name plus latest recovery, sleep, and cycle summaries."""

    async with _whoop_client() as client:
        profile = await client.get_user_profile_basic()
        rec = await client.list_recovery(PaginatedListParams(limit=1))
        slp = await client.list_sleep(PaginatedListParams(limit=1))
        cyc = await client.list_cycles(PaginatedListParams(limit=1))

    r0 = rec.records[0] if rec.records else None
    s0 = slp.records[0] if slp.records else None
    c0 = cyc.records[0] if cyc.records else None

    out: dict[str, Any] = {
        "user": {
            "first_name": profile.first_name,
            "last_name": profile.last_name,
            "email": profile.email,
        },
        "latest_recovery": None,
        "latest_sleep": None,
        "latest_cycle": None,
    }
    if r0 and r0.score:
        out["latest_recovery"] = {
            "cycle_id": r0.cycle_id,
            "recovery_score": r0.score.recovery_score,
            "resting_heart_rate": r0.score.resting_heart_rate,
            "hrv_rmssd_milli": r0.score.hrv_rmssd_milli,
            "score_state": str(r0.score_state),
        }
    if s0 and s0.score:
        out["latest_sleep"] = {
            "sleep_id": s0.id,
            "sleep_performance_percentage": s0.score.sleep_performance_percentage,
            "sleep_efficiency_percentage": s0.score.sleep_efficiency_percentage,
            "nap": s0.nap,
        }
    if c0 and c0.score:
        out["latest_cycle"] = {
            "cycle_id": c0.id,
            "strain": c0.score.strain,
            "kilojoule": c0.score.kilojoule,
        }
    return out


def _configure_logging(settings: WhoopSettings) -> None:
    logging.basicConfig(level=getattr(logging, settings.log_level))


def main() -> None:
    """Run `whoop-mcp login` or the MCP server over stdio."""

    if len(sys.argv) >= 2 and sys.argv[1] == "login":
        from whoop_mcp.cli import login_sync

        login_sync(sys.argv[2:])
        return

    settings = get_settings()
    _configure_logging(settings)
    logger.info("Starting whoop-mcp %s (stdio)", __version__)
    asyncio.run(mcp.run_stdio_async())
