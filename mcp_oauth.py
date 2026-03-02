"""
MCP-native OAuth 2.0 Authorization Server.

Implements the MCP OAuth spec so Claude Desktop can connect via:
  Settings → Connectors → Add custom connector → Enter URL → Done.

Our server acts as an OAuth proxy:
  - Authorization Server to Claude Desktop (this module)
  - OAuth Client to Salesforce (reuses existing SF OAuth)

Endpoints:
  GET  /.well-known/oauth-protected-resource   — RFC 9728 resource metadata
  GET  /.well-known/oauth-authorization-server  — RFC 8414 server metadata
  GET  /oauth/authorize                         — Authorization (redirects to SF)
  POST /oauth/token                             — Token exchange (PKCE verified)
  POST /oauth/register                          — Dynamic Client Registration (RFC 7591)
"""

import hashlib
import hmac
import base64
import os
import time
import logging
import secrets
import urllib.parse

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from token_store import get_token_store, UserTokens
from oauth import (
    _validate_instance_url,
    detect_pardot_business_unit_id,
    SF_OAUTH_CLIENT_ID,
    SF_OAUTH_CLIENT_SECRET,
    SF_OAUTH_LOGIN_URL,
    SF_OAUTH_REDIRECT_URI,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_CODE_TTL_SECONDS = 600  # 10 minutes
MAX_PENDING_CODES = 500
MAX_REGISTERED_CLIENTS = 200
MAX_REFRESH_TOKENS = 1000
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", 86400))

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------

# Authorization codes: code -> { sf_tokens, client_id, redirect_uri, code_challenge, state, created_at }
_auth_codes: dict[str, dict] = {}

# Dynamic client registrations: client_id -> { client_name, redirect_uris, created_at }
_registered_clients: dict[str, dict] = {}

# Refresh tokens: refresh_token -> { session_token, created_at }
_refresh_tokens: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Allowed redirect URI schemes (FIX #6: scheme validation)
# ---------------------------------------------------------------------------

_ALLOWED_REDIRECT_SCHEMES = ("https", "http")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_server_url(request: Request) -> str:
    """Build the external server URL from request headers."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost:8000"))
    return f"{scheme}://{host}"


def _cleanup_expired_codes() -> None:
    """Remove expired authorization codes."""
    now = time.time()
    expired = [c for c, data in _auth_codes.items() if now - data["created_at"] > AUTH_CODE_TTL_SECONDS]
    for c in expired:
        del _auth_codes[c]


def _cleanup_expired_refresh_tokens() -> None:
    """Remove refresh tokens older than 2x session TTL (FIX #4)."""
    now = time.time()
    max_age = SESSION_TTL_SECONDS * 2
    expired = [rt for rt, data in _refresh_tokens.items() if now - data["created_at"] > max_age]
    for rt in expired:
        del _refresh_tokens[rt]


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verify S256 PKCE challenge (FIX #8: timing-safe comparison)."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, code_challenge)


def _validate_redirect_uri(uri: str) -> bool:
    """
    Validate redirect_uri scheme and structure (FIX #1 + #6).
    Only https:// allowed, except http://localhost for development.
    """
    try:
        parsed = urllib.parse.urlparse(uri)
    except Exception:
        return False

    if parsed.scheme not in _ALLOWED_REDIRECT_SCHEMES:
        return False

    # http:// only allowed for localhost (development)
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "[::1]"):
        return False

    # Must have a hostname
    if not parsed.hostname:
        return False

    return True


def _validate_redirect_uri_for_client(client_id: str, redirect_uri: str) -> bool:
    """
    Check redirect_uri against DCR-registered URIs (FIX #1: open redirect).
    If client is registered, redirect_uri must match one of the registered URIs.
    If client is not registered (public client), just validate the scheme.
    """
    client = _registered_clients.get(client_id)
    if client is not None:
        return redirect_uri in client["redirect_uris"]
    # Unregistered client — allow if scheme is valid
    return _validate_redirect_uri(redirect_uri)


def _sanitize_client_name(name: str) -> str:
    """Sanitize client_name for logging and storage (FIX #9)."""
    if not isinstance(name, str):
        return "unnamed"
    # Strip control characters and limit length
    sanitized = "".join(c for c in name if c.isprintable())
    return sanitized[:100] or "unnamed"


# ---------------------------------------------------------------------------
# 1. GET /.well-known/oauth-protected-resource  (RFC 9728)
# ---------------------------------------------------------------------------


async def protected_resource_metadata(request: Request) -> JSONResponse:
    """Return protected resource metadata telling Claude where our auth server is."""
    server_url = _get_server_url(request)
    return JSONResponse({
        "resource": server_url,
        "authorization_servers": [server_url],
        "bearer_methods_supported": ["header"],
    })


# ---------------------------------------------------------------------------
# 2. GET /.well-known/oauth-authorization-server  (RFC 8414)
# ---------------------------------------------------------------------------


async def authorization_server_metadata(request: Request) -> JSONResponse:
    """Return OAuth authorization server metadata (endpoints, PKCE, scopes)."""
    server_url = _get_server_url(request)
    return JSONResponse({
        "issuer": server_url,
        "authorization_endpoint": f"{server_url}/oauth/authorize",
        "token_endpoint": f"{server_url}/oauth/token",
        "registration_endpoint": f"{server_url}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["read", "write"],
    })


# ---------------------------------------------------------------------------
# 3. GET /oauth/authorize  — Authorization endpoint
# ---------------------------------------------------------------------------


async def oauth_authorize(request: Request) -> RedirectResponse | JSONResponse:
    """
    Authorization endpoint. Claude Desktop redirects the user here.
    We redirect to Salesforce OAuth, then on callback redirect back to Claude.
    """
    client_id = request.query_params.get("client_id", "")
    redirect_uri = request.query_params.get("redirect_uri", "")
    state = request.query_params.get("state", "")
    code_challenge = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "")
    scope = request.query_params.get("scope", "")

    # Validate required params
    if not client_id or not redirect_uri or not code_challenge:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing required parameters: client_id, redirect_uri, code_challenge"},
            status_code=400,
        )

    if code_challenge_method and code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Only S256 code_challenge_method is supported"},
            status_code=400,
        )

    # FIX #1 + #6: Validate redirect_uri (scheme + against DCR registration)
    if not _validate_redirect_uri(redirect_uri):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Invalid redirect_uri: must use https (or http://localhost for development)"},
            status_code=400,
        )

    if not _validate_redirect_uri_for_client(client_id, redirect_uri):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uri does not match registered URIs for this client"},
            status_code=400,
        )

    if not SF_OAUTH_CLIENT_ID:
        return JSONResponse(
            {"error": "server_error", "error_description": "OAuth not configured on server"},
            status_code=503,
        )

    _cleanup_expired_codes()

    # FIX #2: Enforce MAX_PENDING_CODES limit
    if len(_auth_codes) >= MAX_PENDING_CODES:
        return JSONResponse(
            {"error": "server_error", "error_description": "Too many pending authorization requests, try again later"},
            status_code=429,
        )

    # Store the MCP OAuth session in an internal state parameter
    # We use a separate internal_state for the SF redirect, and store
    # the Claude-facing params so we can resume after SF callback.
    internal_state = secrets.token_urlsafe(32)

    # Store pending authorization
    _auth_codes[internal_state] = {
        "type": "pending",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "scope": scope,
        "created_at": time.time(),
    }

    # FIX #5: Use configured SF_OAUTH_REDIRECT_URI from env instead of
    # constructing dynamically from request headers (prevents mismatch
    # with SF Connected App and blocks X-Forwarded-Host spoofing)
    sf_redirect_uri = SF_OAUTH_REDIRECT_URI

    # Redirect to Salesforce OAuth
    params = {
        "response_type": "code",
        "client_id": SF_OAUTH_CLIENT_ID,
        "redirect_uri": sf_redirect_uri,
        "state": internal_state,
        "scope": "api refresh_token pardot_api",
    }
    authorize_url = f"{SF_OAUTH_LOGIN_URL}/services/oauth2/authorize?{urllib.parse.urlencode(params)}"

    return RedirectResponse(url=authorize_url)


# ---------------------------------------------------------------------------
# 3b. GET /oauth/callback  — SF OAuth callback (MCP-aware)
# ---------------------------------------------------------------------------


async def mcp_oauth_callback(request: Request):
    """
    Handle Salesforce OAuth callback. If the state matches an MCP OAuth
    pending authorization, generate an auth code and redirect to Claude Desktop.
    Otherwise, fall through to the legacy callback.
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code or not state:
        return None  # Fall through to legacy handler

    # Check if this is an MCP OAuth flow
    pending = _auth_codes.get(state)
    if pending is None or pending.get("type") != "pending":
        return None  # Not an MCP flow — fall through to legacy

    # Remove pending entry
    del _auth_codes[state]

    # Check expiry
    if time.time() - pending["created_at"] > AUTH_CODE_TTL_SECONDS:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Authorization session expired"},
            status_code=400,
        )

    # FIX #5: Use configured SF_OAUTH_REDIRECT_URI from env
    sf_redirect_uri = SF_OAUTH_REDIRECT_URI

    # Exchange SF authorization code for tokens
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SF_OAUTH_LOGIN_URL}/services/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": SF_OAUTH_CLIENT_ID,
                "client_secret": SF_OAUTH_CLIENT_SECRET,
                "redirect_uri": sf_redirect_uri,
            },
        )
        if resp.status_code != 200:
            logger.error("MCP OAuth: SF token exchange failed (HTTP %d)", resp.status_code)
            return JSONResponse(
                {"error": "server_error", "error_description": "Salesforce token exchange failed"},
                status_code=502,
            )
        token_data = resp.json()

    instance_url = token_data.get("instance_url", "")
    if not _validate_instance_url(instance_url):
        logger.error("MCP OAuth: invalid instance_url from SF")
        return JSONResponse(
            {"error": "server_error", "error_description": "Invalid Salesforce instance URL"},
            status_code=502,
        )

    # Auto-detect Pardot Business Unit ID from Salesforce
    pardot_buid = await detect_pardot_business_unit_id(
        token_data["access_token"], instance_url
    )

    # Generate authorization code for Claude Desktop
    auth_code = secrets.token_urlsafe(48)

    _auth_codes[auth_code] = {
        "type": "code",
        "client_id": pending["client_id"],
        "redirect_uri": pending["redirect_uri"],
        "code_challenge": pending["code_challenge"],
        "sf_access_token": token_data["access_token"],
        "sf_refresh_token": token_data.get("refresh_token", ""),
        "sf_instance_url": instance_url,
        "sf_pardot_buid": pardot_buid,
        "created_at": time.time(),
    }

    logger.info("MCP OAuth: auth code generated, redirecting to client")

    # Redirect back to Claude Desktop with the authorization code
    params = {"code": auth_code}
    if pending["state"]:
        params["state"] = pending["state"]

    redirect_url = f"{pending['redirect_uri']}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url=redirect_url)


# ---------------------------------------------------------------------------
# 4. POST /oauth/token  — Token exchange
# ---------------------------------------------------------------------------


async def oauth_token(request: Request) -> JSONResponse:
    """
    Token endpoint. Exchanges authorization code for access token (with PKCE),
    or refreshes an existing token.
    """
    # Parse form body
    try:
        form = await request.form()
    except Exception:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Could not parse request body"},
            status_code=400,
        )

    grant_type = form.get("grant_type", "")

    if grant_type == "authorization_code":
        return await _handle_authorization_code(form)
    elif grant_type == "refresh_token":
        return await _handle_refresh_token(form)
    else:
        return JSONResponse(
            {"error": "unsupported_grant_type", "error_description": f"Unsupported grant_type: {grant_type}"},
            status_code=400,
        )


async def _handle_authorization_code(form) -> JSONResponse:
    """Exchange authorization code for access + refresh token."""
    code = form.get("code", "")
    code_verifier = form.get("code_verifier", "")
    client_id = form.get("client_id", "")
    redirect_uri = form.get("redirect_uri", "")

    if not code or not code_verifier:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing code or code_verifier"},
            status_code=400,
        )

    _cleanup_expired_codes()

    # Look up and consume the authorization code (single-use)
    code_data = _auth_codes.pop(code, None)
    if code_data is None or code_data.get("type") != "code":
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"},
            status_code=400,
        )

    # Check expiry
    if time.time() - code_data["created_at"] > AUTH_CODE_TTL_SECONDS:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Authorization code expired"},
            status_code=400,
        )

    # Validate client_id and redirect_uri match
    if code_data["client_id"] != client_id:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "client_id mismatch"},
            status_code=400,
        )

    if code_data["redirect_uri"] != redirect_uri:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
            status_code=400,
        )

    # Verify PKCE (FIX #8: timing-safe comparison)
    if not verify_pkce(code_verifier, code_data["code_challenge"]):
        logger.warning("MCP OAuth: PKCE verification failed")
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "PKCE verification failed"},
            status_code=400,
        )

    # Generate session token and store SF tokens
    store = get_token_store()
    if not store:
        return JSONResponse(
            {"error": "server_error", "error_description": "Token storage not configured"},
            status_code=500,
        )

    session_token = secrets.token_urlsafe(48)
    refresh_token = secrets.token_urlsafe(48)

    tokens = UserTokens(
        access_token=code_data["sf_access_token"],
        refresh_token=code_data["sf_refresh_token"],
        instance_url=code_data["sf_instance_url"],
        issued_at=time.time(),
        pardot_business_unit_id=code_data.get("sf_pardot_buid"),
    )
    store.put(session_token, tokens)

    # FIX #4: Store refresh token with timestamp for cleanup
    _cleanup_expired_refresh_tokens()
    _refresh_tokens[refresh_token] = {
        "session_token": session_token,
        "created_at": time.time(),
    }

    logger.info("MCP OAuth: session created via token exchange")

    return JSONResponse({
        "access_token": session_token,
        "token_type": "Bearer",
        "expires_in": SESSION_TTL_SECONDS,
        "refresh_token": refresh_token,
    })


async def _handle_refresh_token(form) -> JSONResponse:
    """Refresh an expired session token."""
    refresh_token = form.get("refresh_token", "")
    if not refresh_token:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing refresh_token"},
            status_code=400,
        )

    # FIX #4: Updated structure — dict with session_token + created_at
    rt_data = _refresh_tokens.pop(refresh_token, None)
    if rt_data is None:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid refresh token"},
            status_code=400,
        )

    old_session_token = rt_data["session_token"]

    store = get_token_store()
    if not store:
        return JSONResponse(
            {"error": "server_error", "error_description": "Token storage not configured"},
            status_code=500,
        )

    # Get SF tokens from old session
    old_tokens = store.get(old_session_token)
    if old_tokens is None:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Session expired, please re-authenticate"},
            status_code=400,
        )

    # Try to refresh SF access token using SF refresh token
    sf_refresh_token = old_tokens.get("refresh_token", "")
    if sf_refresh_token:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{SF_OAUTH_LOGIN_URL}/services/oauth2/token",
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": sf_refresh_token,
                        "client_id": SF_OAUTH_CLIENT_ID,
                        "client_secret": SF_OAUTH_CLIENT_SECRET,
                    },
                )
                if resp.status_code == 200:
                    sf_data = resp.json()
                    new_instance = sf_data.get("instance_url", old_tokens["instance_url"])
                    # FIX #7: Validate instance_url from SF refresh response
                    if _validate_instance_url(new_instance):
                        old_tokens["access_token"] = sf_data["access_token"]
                        old_tokens["instance_url"] = new_instance
                    else:
                        logger.warning("MCP OAuth: SF refresh returned invalid instance_url, keeping old")
                        old_tokens["access_token"] = sf_data["access_token"]
                else:
                    logger.warning("MCP OAuth: SF refresh failed (HTTP %d)", resp.status_code)
        except Exception as e:
            logger.warning("MCP OAuth: SF refresh error: %s", e)

    # Re-detect Pardot BUID if missing (e.g., session created before auto-detect)
    pardot_buid = old_tokens.get("pardot_business_unit_id")
    if not pardot_buid:
        pardot_buid = await detect_pardot_business_unit_id(
            old_tokens["access_token"], old_tokens["instance_url"]
        )

    # Generate new session token
    new_session_token = secrets.token_urlsafe(48)
    new_refresh_token = secrets.token_urlsafe(48)

    new_tokens = UserTokens(
        access_token=old_tokens["access_token"],
        refresh_token=old_tokens.get("refresh_token", ""),
        instance_url=old_tokens["instance_url"],
        issued_at=time.time(),
        pardot_business_unit_id=pardot_buid,
    )
    store.put(new_session_token, new_tokens)

    # Remove old session
    store.delete(old_session_token)

    # FIX #4: Store refresh token with timestamp
    _cleanup_expired_refresh_tokens()
    _refresh_tokens[new_refresh_token] = {
        "session_token": new_session_token,
        "created_at": time.time(),
    }

    logger.info("MCP OAuth: session refreshed")

    return JSONResponse({
        "access_token": new_session_token,
        "token_type": "Bearer",
        "expires_in": SESSION_TTL_SECONDS,
        "refresh_token": new_refresh_token,
    })


# ---------------------------------------------------------------------------
# 5. POST /oauth/register  — Dynamic Client Registration (RFC 7591)
# ---------------------------------------------------------------------------


async def oauth_register(request: Request) -> JSONResponse:
    """Register a dynamic OAuth client (used by Claude Desktop on first connect)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Invalid JSON body"},
            status_code=400,
        )

    # FIX #9: Sanitize client_name
    client_name = _sanitize_client_name(body.get("client_name", "unnamed"))
    redirect_uris = body.get("redirect_uris", [])
    grant_types = body.get("grant_types", ["authorization_code"])
    response_types = body.get("response_types", ["code"])
    token_endpoint_auth_method = body.get("token_endpoint_auth_method", "none")

    if not redirect_uris:
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": "redirect_uris is required"},
            status_code=400,
        )

    # FIX #6: Validate all redirect_uris
    if not isinstance(redirect_uris, list):
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": "redirect_uris must be a list"},
            status_code=400,
        )

    for uri in redirect_uris:
        if not isinstance(uri, str) or not _validate_redirect_uri(uri):
            return JSONResponse(
                {"error": "invalid_client_metadata",
                 "error_description": "Invalid redirect_uri: must use https (or http://localhost for development)"},
                status_code=400,
            )

    # FIX #3: Enforce MAX_REGISTERED_CLIENTS limit
    if len(_registered_clients) >= MAX_REGISTERED_CLIENTS:
        return JSONResponse(
            {"error": "server_error", "error_description": "Maximum number of registered clients reached"},
            status_code=429,
        )

    # Generate client credentials
    client_id = secrets.token_urlsafe(32)

    _registered_clients[client_id] = {
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": token_endpoint_auth_method,
        "created_at": time.time(),
    }

    logger.info("MCP OAuth: registered client (id=%s...)", client_id[:8])

    return JSONResponse(
        {
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
            "token_endpoint_auth_method": token_endpoint_auth_method,
        },
        status_code=201,
    )
