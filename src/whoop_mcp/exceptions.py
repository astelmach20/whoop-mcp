"""WHOOP OAuth and Developer API error types (no silent failures)."""

from __future__ import annotations


class WhoopError(Exception):
    """Base error for this package."""


class WhoopOAuthError(WhoopError):
    """Token endpoint returned a non-success status or an invalid payload."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        response_text: str | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text
        self.error_code = error_code

    @property
    def is_retryable(self) -> bool:
        """True when retrying the same request could plausibly succeed."""

        return False


class WhoopOAuthServerError(WhoopOAuthError):
    """Token endpoint returned 5xx (or the transport failed) — outcome indeterminate.

    WHOOP rotates refresh tokens server-side *before* delivering the response and
    provides no overlap window, so a lost response (502, timeout, dropped
    connection) may mean the refresh token was consumed even though we never
    received the replacement. That is unrecoverable and requires re-authorization,
    which is why these are retried aggressively before giving up.
    """

    @property
    def is_retryable(self) -> bool:
        return True


class WhoopRefreshTokenRejected(WhoopOAuthError):
    """WHOOP rejected the refresh token itself (HTTP 400 invalid_grant/invalid_request).

    Terminal: the token is dead and no number of retries will revive it. The user
    must re-run the authorization code flow (`whoop-mcp login`).
    """


class WhoopClientAuthError(WhoopOAuthError):
    """Client authentication failed (HTTP 401 invalid_client).

    Indicates a misconfigured `client_id`/`client_secret`, or that credentials were
    sent using an auth method the client is not registered for. WHOOP clients are
    typically registered `client_secret_post`, meaning credentials must be sent in
    the request body rather than as an HTTP Basic auth header. Not a token problem.
    """


class WhoopApiError(WhoopError):
    """Developer API request failed (after transport; HTTP layer)."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        method: str,
        url: str,
        response_text: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.method = method
        self.url = url
        self.response_text = response_text


class TokenStoreError(WhoopError):
    """Token file is missing, unreadable, or violates the expected schema."""

    def __init__(self, message: str, *, path: str | None = None) -> None:
        super().__init__(message)
        self.path = path


class TokenRefreshError(WhoopError):
    """Refresh token flow failed or no refresh token is available."""
