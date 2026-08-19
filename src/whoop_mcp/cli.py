"""First-time OAuth login via localhost callback (run outside the stdio MCP server)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import queue
import secrets
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlparse

import httpx

from whoop_mcp.exceptions import WhoopOAuthError
from whoop_mcp.models import TokenBundle
from whoop_mcp.oauth import build_authorization_url, exchange_authorization_code
from whoop_mcp.settings import get_settings
from whoop_mcp.token_store import FileTokenStore

logger = logging.getLogger(__name__)


def _callback_path(redirect_uri: str) -> str:
    u = urlparse(redirect_uri)
    return u.path or "/"


def _wait_for_authorization_code(
    redirect_uri: str,
    *,
    expected_state: str,
    auth_url: str,
    open_browser: bool,
    timeout_s: float,
) -> str:
    rp = urlparse(redirect_uri)
    host = rp.hostname or "127.0.0.1"
    port = rp.port
    if port is None:
        msg = (
            "WHOOP_REDIRECT_URI must include an explicit port for local login "
            "(e.g. http://127.0.0.1:8780/callback). Register the same URI in the WHOOP dashboard."
        )
        raise SystemExit(msg)

    path = _callback_path(redirect_uri)
    result: queue.Queue[str | Exception] = queue.Queue()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            logger.debug("%s - %s", self.address_string(), fmt % args)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path != path:
                self.send_error(404)
                return
            qs = parse_qs(parsed.query)
            if qs.get("error"):
                err = qs["error"][0]
                desc = qs.get("error_description", [""])[0]
                result.put(
                    WhoopOAuthError(
                        f"Authorization failed: {err} {desc}",
                        response_text=desc or None,
                    ),
                )
                self.send_response(400)
                self.end_headers()
                return
            codes = qs.get("code", [])
            states = qs.get("state", [])
            if len(codes) != 1 or len(states) != 1:
                result.put(ValueError("Expected query parameters `code` and `state`."))
                self.send_error(400)
                return
            if states[0] != expected_state:
                result.put(ValueError("Parameter `state` did not match (CSRF check failed)."))
                self.send_response(400)
                self.end_headers()
                return
            result.put(codes[0])
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            body = (
                b"<html><body><p>Authorization complete. You can close this window."
                b"</p></body></html>"
            )
            self.wfile.write(body)

    server = HTTPServer((host, port), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if open_browser:
            webbrowser.open(auth_url)
        else:
            print("Open this URL in a browser:\n", auth_url, sep="", file=sys.stderr)
        item = result.get(timeout=timeout_s)
        if isinstance(item, Exception):
            raise item
        return item
    finally:
        server.shutdown()
        server.server_close()


async def login_main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="WHOOP OAuth login (localhost redirect).")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Print the authorize URL instead of opening a browser.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=600.0,
        help="Seconds to wait for the browser redirect (default: 600).",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    # WHOOP requires >= 8 chars; use full entropy rather than the 8-char minimum.
    state = secrets.token_urlsafe(32)
    auth_url = build_authorization_url(settings, state=state)

    code = await asyncio.to_thread(
        _wait_for_authorization_code,
        str(settings.redirect_uri),
        expected_state=state,
        auth_url=auth_url,
        open_browser=not args.no_browser,
        timeout_s=args.timeout,
    )

    async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
        oauth = await exchange_authorization_code(settings, code=code, httpx_client=client)

    bundle = TokenBundle.from_oauth_response(oauth)
    store = FileTokenStore(Path(settings.token_store_path))
    store.save(bundle)
    print(f"Saved tokens to {settings.token_store_path}", file=sys.stderr)


def login_sync(argv: list[str] | None = None) -> None:
    asyncio.run(login_main(argv))
