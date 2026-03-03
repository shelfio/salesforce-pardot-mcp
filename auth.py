"""
Bearer token authentication middleware for the MCP server.

Validates session tokens (from MCP OAuth 2.1 flow) against the encrypted
token store.  Includes audit logging (SHA-256 fingerprint) and per-key
rate limiting.
"""

import hashlib
import os
import logging
import time
from collections import defaultdict

from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers
from user_context import current_api_key

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_REQUESTS_PER_MINUTE = 60

# ---------------------------------------------------------------------------
# Rate limiting (sliding window, per-key)
# ---------------------------------------------------------------------------

_request_timestamps: dict[str, list[float]] = defaultdict(list)
_rl_call_count = 0


def _check_rate_limit(token: str) -> None:
    """
    Enforce a sliding-window rate limit of MAX_REQUESTS_PER_MINUTE per key.
    Raises ValueError if the limit is exceeded.
    """
    global _rl_call_count
    _rl_call_count += 1

    # Periodic cleanup of stale entries to prevent memory leak
    if _rl_call_count % 100 == 0:
        now = time.monotonic()
        stale = [k for k, v in _request_timestamps.items() if not v or now - v[-1] > 60]
        for k in stale:
            del _request_timestamps[k]

    fp = _key_fingerprint(token)
    now = time.monotonic()
    window = [t for t in _request_timestamps[fp] if now - t < 60]
    if len(window) >= MAX_REQUESTS_PER_MINUTE:
        logger.warning("Rate limit exceeded for key:%s", fp)
        raise ValueError(f"Rate limit exceeded: max {MAX_REQUESTS_PER_MINUTE} requests/minute")
    window.append(now)
    _request_timestamps[fp] = window


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _key_fingerprint(token: str) -> str:
    """Return first 8 hex chars of the SHA-256 hash of a key (for safe logging)."""
    return hashlib.sha256(token.encode()).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class BearerAuthMiddleware(Middleware):
    """
    FastMCP middleware that gates every MCP request behind a bearer token.

    Validates session tokens from the MCP OAuth 2.1 flow against the
    encrypted token store.

    After successful authentication:
    - Sets current_api_key ContextVar for per-user tool routing
    - Logs an audit entry with the key fingerprint and MCP method
    - Enforces per-key rate limiting (sliding window)
    """

    async def on_request(
        self,
        context: MiddlewareContext,
        call_next,
    ):
        # --- Skip auth only in stdio mode (local Claude Desktop, not remote) ---
        if (
            os.environ.get("SKIP_AUTH", "").lower() in ("1", "true", "yes")
            and os.environ.get("MCP_TRANSPORT", "sse").lower() == "stdio"
        ):
            return await call_next(context)

        # --- Extract bearer token ---
        # FastMCP excludes "authorization" header by default — explicitly include it
        headers = get_http_headers(include={"authorization"}) or {}
        auth_header = headers.get("authorization", "")

        if not auth_header.lower().startswith("bearer "):
            logger.warning("Rejected request — missing or malformed Authorization header")
            raise ValueError(
                "Unauthorized: missing Bearer token",
            )

        token = auth_header.split(" ", 1)[1]

        # --- Validate session token ---
        from token_store import get_token_store

        store = get_token_store()
        if not store or not store.has_tokens(token):
            logger.warning("Rejected request — invalid token")
            raise ValueError("Unauthorized: invalid token")

        # --- Rate limiting ---
        _check_rate_limit(token)

        # --- Audit log ---
        logger.info(
            "Authorized — key:%s method:%s",
            _key_fingerprint(token),
            context.method,
        )

        # --- Set user context for per-user client routing ---
        token_var = current_api_key.set(token)
        try:
            return await call_next(context)
        finally:
            current_api_key.reset(token_var)
