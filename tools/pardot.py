"""
Pardot (Marketing Cloud Account Engagement) API v5 tools for the MCP server.

Provides prospect, campaign, list, form, visitor activity, email, and
lifecycle history operations via async HTTP calls. Token caching with
55-minute TTL avoids re-authenticating on every request.

Supports multi-tenant mode: when a user has connected their own Salesforce
account via OAuth, Pardot tools use their access token and Business Unit ID.
"""

import os
import time
import logging
from typing import Annotated, Any

import httpx
from pydantic import Field
from fastmcp.exceptions import ToolError

from user_context import get_current_api_key
from token_store import get_token_store

logger = logging.getLogger(__name__)

PARDOT_BASE_URL = "https://pi.pardot.com/api/v5/objects"
TOKEN_TTL_SECONDS = 55 * 60  # 55 minutes


# ---------------------------------------------------------------------------
# Pardot HTTP client with token caching
# ---------------------------------------------------------------------------


class PardotClient:
    """
    Async HTTP client for Pardot API v5.

    In legacy mode, obtains its access token from the shared Salesforce
    client's ``session_id``. In multi-tenant mode, uses per-user OAuth
    tokens from the token store. On 401 responses the cached token is
    invalidated and the request is retried once.
    """

    def __init__(self, api_key: str | None = None) -> None:
        self._token: str | None = None
        self._token_acquired_at: float = 0.0
        self._http_client: httpx.AsyncClient | None = None
        self._api_key = api_key  # None = legacy mode

    # -- Token management ---------------------------------------------------

    def _token_is_valid(self) -> bool:
        if self._token is None:
            return False
        return (time.monotonic() - self._token_acquired_at) < TOKEN_TTL_SECONDS

    def _refresh_token(self) -> str:
        """
        Get a fresh access token.

        Per-user mode: reads from token store.
        Legacy mode: reads from shared Salesforce client session_id.
        """
        # Try per-user OAuth tokens first
        store = get_token_store()
        if self._api_key and store:
            tokens = store.get(self._api_key)
            if tokens:
                self._token = tokens["access_token"]
                self._token_acquired_at = time.monotonic()
                logger.info("Pardot token refreshed from OAuth store (TTL: %d min)", TOKEN_TTL_SECONDS // 60)
                return self._token

        # Fallback to legacy: get token from shared SF client
        from tools.salesforce import get_sf_client

        sf = get_sf_client()
        token = sf.session_id
        if not token:
            raise ToolError("Could not obtain access token from Salesforce client")
        self._token = token
        self._token_acquired_at = time.monotonic()
        logger.info("Pardot access token refreshed from legacy SF (TTL: %d min)", TOKEN_TTL_SECONDS // 60)
        return token

    def _get_token(self) -> str:
        if not self._token_is_valid():
            return self._refresh_token()
        return self._token  # type: ignore[return-value]

    def _invalidate_token(self) -> None:
        """Force token refresh on next request."""
        self._token = None

    # -- HTTP helpers -------------------------------------------------------

    @staticmethod
    def _sanitize_buid(value: str) -> str:
        """Validate BUID is alphanumeric to prevent HTTP header injection."""
        if value and value.isalnum():
            return value
        return ""

    def _headers(self) -> dict[str, str]:
        buid = ""
        # Per-user BUID from token store (auto-detected during OAuth)
        store = get_token_store()
        if self._api_key and store:
            tokens = store.get(self._api_key)
            if tokens and tokens.get("pardot_business_unit_id"):
                buid = self._sanitize_buid(tokens["pardot_business_unit_id"])
        # Fallback to shared env var
        if not buid:
            buid = self._sanitize_buid(os.environ.get("PARDOT_BUSINESS_UNIT_ID", ""))
        if not buid:
            logger.warning(
                "Pardot-Business-Unit-Id is empty — Pardot API calls will fail "
                "(error 181). Set PARDOT_BUSINESS_UNIT_ID env var or re-authenticate."
            )
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Pardot-Business-Unit-Id": buid,
            "Content-Type": "application/json",
        }

    async def _client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict:
        """GET request to Pardot API v5 with 401-retry."""
        client = await self._client()
        url = f"{PARDOT_BASE_URL}/{path}"
        try:
            resp = await client.get(url, headers=self._headers(), params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                logger.warning("Pardot 401 — refreshing token and retrying")
                self._invalidate_token()
                resp = await client.get(url, headers=self._headers(), params=params)
                resp.raise_for_status()
                return resp.json()
            raise ToolError(
                f"Pardot API error {exc.response.status_code}: {exc.response.text}"
            )
        except httpx.RequestError as exc:
            raise ToolError(f"Pardot API request failed: {exc}")

    async def post(self, path: str, json_body: dict[str, Any] | None = None) -> dict:
        """POST request to Pardot API v5 with 401-retry."""
        client = await self._client()
        url = f"{PARDOT_BASE_URL}/{path}"
        try:
            resp = await client.post(url, headers=self._headers(), json=json_body)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                logger.warning("Pardot 401 — refreshing token and retrying")
                self._invalidate_token()
                resp = await client.post(url, headers=self._headers(), json=json_body)
                resp.raise_for_status()
                return resp.json()
            raise ToolError(
                f"Pardot API error {exc.response.status_code}: {exc.response.text}"
            )
        except httpx.RequestError as exc:
            raise ToolError(f"Pardot API request failed: {exc}")

    async def patch(self, path: str, json_body: dict[str, Any] | None = None) -> dict:
        """PATCH request to Pardot API v5 with 401-retry."""
        client = await self._client()
        url = f"{PARDOT_BASE_URL}/{path}"
        try:
            resp = await client.patch(url, headers=self._headers(), json=json_body)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                logger.warning("Pardot 401 — refreshing token and retrying")
                self._invalidate_token()
                resp = await client.patch(url, headers=self._headers(), json=json_body)
                resp.raise_for_status()
                return resp.json()
            raise ToolError(
                f"Pardot API error {exc.response.status_code}: {exc.response.text}"
            )
        except httpx.RequestError as exc:
            raise ToolError(f"Pardot API request failed: {exc}")


# ---------------------------------------------------------------------------
# Client management (per-user + legacy singleton)
# ---------------------------------------------------------------------------

_pardot_clients: dict[str, tuple[PardotClient, float]] = {}
_pardot_client_legacy: PardotClient | None = None
_MAX_PARDOT_CLIENTS = 50


def get_pardot_client() -> PardotClient:
    """Get per-user or legacy Pardot client based on current request context."""
    global _pardot_client_legacy
    api_key = get_current_api_key()

    if api_key:
        store = get_token_store()
        if store and store.has_tokens(api_key):
            now = time.monotonic()
            if api_key in _pardot_clients:
                client, created = _pardot_clients[api_key]
                if (now - created) < TOKEN_TTL_SECONDS:
                    return client
            # Evict expired entries before adding
            if len(_pardot_clients) >= _MAX_PARDOT_CLIENTS:
                expired = [k for k, (_, t) in _pardot_clients.items() if (now - t) >= TOKEN_TTL_SECONDS]
                for k in expired:
                    del _pardot_clients[k]
                if len(_pardot_clients) >= _MAX_PARDOT_CLIENTS:
                    oldest_key = min(_pardot_clients, key=lambda k: _pardot_clients[k][1])
                    del _pardot_clients[oldest_key]
            client = PardotClient(api_key=api_key)
            _pardot_clients[api_key] = (client, now)
            return client

    # Legacy singleton
    if _pardot_client_legacy is None:
        _pardot_client_legacy = PardotClient()
    return _pardot_client_legacy


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


async def pardot_get_prospects(
    email: Annotated[
        str | None, Field(description="Filter prospects by email address")
    ] = None,
    score_gte: Annotated[
        int | None, Field(description="Minimum prospect score (inclusive)", ge=0)
    ] = None,
    campaign_id: Annotated[
        str | None, Field(description="Filter by Pardot campaign ID")
    ] = None,
) -> dict:
    """Get Pardot prospects with optional filters for email, minimum score, and campaign."""
    client = get_pardot_client()
    params: dict[str, Any] = {
        "fields": "id,email,firstName,lastName,score,campaignId,createdAt,updatedAt",
    }
    if email:
        params["email"] = email

    result = await client.get("prospects", params=params)
    prospects: list[dict] = result.get("values", [])

    # Client-side filtering (Pardot v5 query API doesn't support these natively)
    if score_gte is not None:
        prospects = [p for p in prospects if (p.get("score") or 0) >= score_gte]
    if campaign_id is not None:
        prospects = [
            p for p in prospects if str(p.get("campaignId", "")) == str(campaign_id)
        ]

    return {"count": len(prospects), "prospects": prospects}


async def pardot_get_prospect_by_email(
    email: Annotated[str, Field(description="Email address of the prospect to look up")],
) -> dict:
    """Get a single Pardot prospect by their email address."""
    client = get_pardot_client()
    result = await client.get("prospects", params={"email": email})
    prospects: list[dict] = result.get("values", [])
    if not prospects:
        raise ToolError(f"No prospect found with email: {email}")
    return {"prospect": prospects[0]}


# Pardot fields that cannot be changed through update tools
BLOCKED_PROSPECT_FIELDS: frozenset[str] = frozenset(
    {"email", "score", "grade", "isDoNotEmail", "isDoNotCall",
     "salesforceId", "crmContactFid", "crmLeadFid"}
)


def _check_blocked_prospect_fields(fields: dict) -> None:
    """Raise ToolError if any field key is in the blocked set."""
    found = {k for k in fields if k in BLOCKED_PROSPECT_FIELDS}
    if found:
        raise ToolError(f"Cannot update protected Prospect fields: {found}")


async def pardot_update_prospect(
    prospect_id: Annotated[str, Field(description="Pardot prospect ID to update")],
    fields: Annotated[
        dict,
        Field(
            description=(
                "Dictionary of fields to update, "
                "e.g. {'firstName': 'Jane', 'company': 'Acme Inc.'}"
            )
        ),
    ],
) -> dict:
    """Update a Pardot prospect by ID with the given field values."""
    client = get_pardot_client()
    if not prospect_id or not fields:
        raise ToolError("Both prospect_id and fields are required")
    _check_blocked_prospect_fields(fields)
    result = await client.patch(f"prospects/{prospect_id}", json_body=fields)
    return {"success": True, "prospect": result}


async def pardot_get_campaigns() -> dict:
    """List all Pardot campaigns."""
    client = get_pardot_client()
    result = await client.get("campaigns", params={"fields": "id,name,cost"})
    return {"campaigns": result.get("values", [])}


async def pardot_get_lists() -> dict:
    """List all Pardot lists."""
    client = get_pardot_client()
    result = await client.get(
        "lists", params={"fields": "id,name,title,description,createdAt"}
    )
    return {"lists": result.get("values", [])}


async def pardot_get_forms() -> dict:
    """List all Pardot forms."""
    client = get_pardot_client()
    result = await client.get(
        "forms", params={"fields": "id,name,campaignId,createdAt"}
    )
    return {"forms": result.get("values", [])}


async def pardot_add_prospect_to_list(
    prospect_id: Annotated[str, Field(description="Pardot prospect ID to add")],
    list_id: Annotated[str, Field(description="Pardot list ID to add the prospect to")],
) -> dict:
    """Add a prospect to a Pardot list by creating a list membership."""
    client = get_pardot_client()
    if not prospect_id or not list_id:
        raise ToolError("Both prospect_id and list_id are required")
    body = {"prospectId": int(prospect_id), "listId": int(list_id)}
    result = await client.post("list-memberships", json_body=body)
    return {"success": True, "membership": result}


# ---------------------------------------------------------------------------
# Activity tools
# ---------------------------------------------------------------------------


async def pardot_get_visitor_activities(
    prospect_id: Annotated[str | None, Field(description="Filter by Pardot prospect ID")] = None,
    activity_type: Annotated[int | None, Field(description="Activity type code (1=click, 2=view, 6=form, 11=email open, etc.)")] = None,
    created_after: Annotated[str | None, Field(description="Only activities after this datetime (ISO 8601)")] = None,
    created_before: Annotated[str | None, Field(description="Only activities before this datetime (ISO 8601)")] = None,
) -> dict:
    """Get Pardot visitor activities with optional filters for prospect, type, and date range."""
    client = get_pardot_client()
    params: dict[str, Any] = {
        "fields": "id,prospectId,type,typeName,details,campaignId,createdAt",
    }
    if prospect_id:
        params["prospectId"] = prospect_id
    if activity_type is not None:
        params["type"] = str(activity_type)
    if created_after:
        params["createdAfter"] = created_after
    if created_before:
        params["createdBefore"] = created_before

    result = await client.get("visitor-activities", params=params)
    return {"activities": result.get("values", [])}


async def pardot_get_form_handlers() -> dict:
    """List all Pardot form handlers."""
    client = get_pardot_client()
    result = await client.get(
        "form-handlers", params={"fields": "id,name,url,campaignId,createdAt"}
    )
    return {"form_handlers": result.get("values", [])}


async def pardot_get_emails() -> dict:
    """List Pardot email templates and sends."""
    client = get_pardot_client()
    result = await client.get(
        "emails", params={"fields": "id,name,subject,campaignId,createdAt"}
    )
    return {"emails": result.get("values", [])}


async def pardot_get_lifecycle_history(
    prospect_id: Annotated[str, Field(description="Pardot prospect ID to get lifecycle history for")],
) -> dict:
    """Get lifecycle stage progression history for a Pardot prospect."""
    client = get_pardot_client()
    result = await client.get(
        "lifecycle-histories",
        params={
            "prospectId": prospect_id,
            "fields": "id,prospectId,previousStageId,nextStageId,secondsInStage,createdAt",
        },
    )
    return {"lifecycle_history": result.get("values", [])}


# ---------------------------------------------------------------------------
# Configuration tools
# ---------------------------------------------------------------------------

_BUID_PREFIX = "0Uv"


async def pardot_set_business_unit(
    pardot_business_unit_id: Annotated[
        str,
        Field(
            description=(
                "Pardot Business Unit ID (starts with '0Uv', 15 or 18 characters). "
                "Find it in Salesforce Setup → Quick Find → 'Business Unit Setup'."
            )
        ),
    ],
) -> dict:
    """Set the Pardot Business Unit ID for the current session.

    Use this tool when Pardot API calls fail with error 181 (missing
    Business Unit ID). The BUID is normally auto-detected during OAuth,
    but some orgs require it to be set manually.
    """
    api_key = get_current_api_key()
    if not api_key:
        raise ToolError("No active session — authenticate first")

    store = get_token_store()
    if not store:
        raise ToolError("Token storage not configured on this server")

    tokens = store.get(api_key)
    if not tokens:
        raise ToolError("Session not found or expired — re-authenticate")

    buid = pardot_business_unit_id.strip()
    if (
        not buid
        or not buid.startswith(_BUID_PREFIX)
        or len(buid) not in (15, 18)
        or not buid.isalnum()
    ):
        raise ToolError(
            "Invalid Business Unit ID. Must start with '0Uv' and be 15 or 18 "
            "alphanumeric characters. Find it in Salesforce Setup → Quick Find "
            "→ 'Business Unit Setup'."
        )

    # Copy to avoid mutating the cache outside of the store lock
    updated = dict(tokens)
    updated["pardot_business_unit_id"] = buid
    store.put(api_key, updated)

    return {"success": True, "pardot_business_unit_id": buid}
