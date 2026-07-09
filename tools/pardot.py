"""
Pardot (Marketing Cloud Account Engagement) API v5 tools for the MCP server.

Provides prospect, campaign, list, form, visitor activity, email, and
lifecycle history operations via async HTTP calls. Token caching with
55-minute TTL avoids re-authenticating on every request.

Each user connects their own Salesforce org via MCP OAuth 2.1.
Pardot tools use the authenticated user's access token and Business Unit ID.
"""

import asyncio
import os
import time
import logging
from typing import Annotated, Any

import httpx
from pydantic import Field
from fastmcp.exceptions import ToolError

from user_context import get_current_api_key
from token_store import get_token_store, _hash_key as _cache_key
from tools.salesforce import _refresh_oauth_token

logger = logging.getLogger(__name__)

PARDOT_BASE_URL = "https://pi.pardot.com/api/v5/objects"
TOKEN_TTL_SECONDS = 55 * 60  # 55 minutes

# Anomaly detection & output sanitization
LARGE_RESULT_THRESHOLD = 1000
MAX_RESULT_RECORDS = 500


def _warn_large_result(tool_name: str, count: int) -> None:
    """Log a warning if a Pardot query returned an unusually large result set."""
    if count > LARGE_RESULT_THRESHOLD:
        logger.warning(
            "Large result set from %s: %d records returned (threshold: %d)",
            tool_name, count, LARGE_RESULT_THRESHOLD,
        )


def _safe_error(text: str, max_len: int = 200) -> str:
    """Truncate error response text to prevent leaking org details."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "... [truncated]"


def _validate_numeric_id(value: str, name: str) -> int:
    """Validate that value is a numeric string and return it as int. Prevents path injection."""
    if not value or not value.strip().isdigit():
        raise ToolError(f"Invalid {name}: must be a numeric ID, got {value!r}")
    return int(value.strip())


# ---------------------------------------------------------------------------
# Pardot HTTP client with token caching
# ---------------------------------------------------------------------------


class PardotClient:
    """
    Async HTTP client for Pardot API v5.

    Uses per-user OAuth tokens from the token store. On 401 responses
    the cached token is invalidated and the request is retried once.
    """

    def __init__(self, api_key: str) -> None:
        self._token: str | None = None
        self._token_acquired_at: float = 0.0
        self._http_client: httpx.AsyncClient | None = None
        self._api_key = api_key

    # -- Token management ---------------------------------------------------

    def _token_is_valid(self) -> bool:
        if self._token is None:
            return False
        return (time.monotonic() - self._token_acquired_at) < TOKEN_TTL_SECONDS

    def _refresh_token(self) -> str:
        """Get a fresh access token from the OAuth token store."""
        store = get_token_store()
        if store:
            tokens = store.get(self._api_key)
            if tokens:
                self._token = tokens["access_token"]
                self._token_acquired_at = time.monotonic()
                logger.info("Pardot token refreshed from OAuth store (TTL: %d min)", TOKEN_TTL_SECONDS // 60)
                return self._token
        raise ToolError("No Salesforce tokens found for this session. Please reconnect via OAuth.")

    def _get_token(self) -> str:
        if not self._token_is_valid():
            return self._refresh_token()
        return self._token  # type: ignore[return-value]

    def _invalidate_token(self) -> None:
        """Force token refresh on next request."""
        self._token = None

    async def _force_oauth_refresh(self) -> None:
        """Refresh the Salesforce access token upstream after a Pardot 401.

        Pardot rejects the token when the underlying SF session expired
        (org session timeout), so re-reading the stored copy is not enough —
        the store itself holds the same expired token.
        """
        self._invalidate_token()
        store = get_token_store()
        tokens = store.get(self._api_key) if store else None
        if tokens and tokens.get("refresh_token"):
            new_tokens = await asyncio.to_thread(_refresh_oauth_token, dict(tokens))
            if new_tokens:
                store.put(self._api_key, new_tokens)

    # -- HTTP helpers -------------------------------------------------------

    @staticmethod
    def _sanitize_buid(value: str) -> str:
        """Validate BUID is alphanumeric to prevent HTTP header injection."""
        if value and value.isalnum():
            return value
        return ""

    def _get_buid(self) -> str:
        """Resolve Business Unit ID from token store or env var."""
        buid = ""
        store = get_token_store()
        if self._api_key and store:
            tokens = store.get(self._api_key)
            if tokens and tokens.get("pardot_business_unit_id"):
                buid = self._sanitize_buid(tokens["pardot_business_unit_id"])
        if not buid:
            buid = self._sanitize_buid(os.environ.get("PARDOT_BUSINESS_UNIT_ID", ""))
        return buid

    def _headers(self) -> dict[str, str]:
        buid = self._get_buid()
        if not buid:
            raise ToolError(
                "Pardot Business Unit ID is not configured. "
                "Use the pardot_set_business_unit tool to set it. "
                "Find it in Salesforce Setup → Quick Find → 'Business Unit Setup' "
                "(starts with '0Uv', 15 or 18 characters)."
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
                await self._force_oauth_refresh()
                resp = await client.get(url, headers=self._headers(), params=params)
                resp.raise_for_status()
                return resp.json()
            raise ToolError(
                f"Pardot API error {exc.response.status_code}: {_safe_error(exc.response.text)}"
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
                await self._force_oauth_refresh()
                resp = await client.post(url, headers=self._headers(), json=json_body)
                resp.raise_for_status()
                return resp.json()
            raise ToolError(
                f"Pardot API error {exc.response.status_code}: {_safe_error(exc.response.text)}"
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
                await self._force_oauth_refresh()
                resp = await client.patch(url, headers=self._headers(), json=json_body)
                resp.raise_for_status()
                return resp.json()
            raise ToolError(
                f"Pardot API error {exc.response.status_code}: {_safe_error(exc.response.text)}"
            )
        except httpx.RequestError as exc:
            raise ToolError(f"Pardot API request failed: {exc}")


# ---------------------------------------------------------------------------
# Client management (per-user via OAuth)
# ---------------------------------------------------------------------------

_pardot_clients: dict[str, tuple[PardotClient, float]] = {}
_MAX_PARDOT_CLIENTS = 50


def _close_pardot_http_client(pardot_client: PardotClient) -> None:
    """Schedule async close of a PardotClient's httpx client."""
    if pardot_client._http_client and not pardot_client._http_client.is_closed:
        try:
            loop = asyncio.get_event_loop()
            loop.create_task(pardot_client._http_client.aclose())
        except RuntimeError:
            pass  # No event loop available; client will be GC'd


def get_pardot_client() -> PardotClient:
    """Get per-user Pardot client based on current request context."""
    api_key = get_current_api_key()
    if not api_key:
        raise ToolError("No authenticated session. Please connect via MCP OAuth.")

    # Use HMAC-hashed key for cache (prevents raw token exposure in memory dumps)
    hk = _cache_key(api_key)

    now = time.monotonic()
    if hk in _pardot_clients:
        client, created = _pardot_clients[hk]
        if (now - created) < TOKEN_TTL_SECONDS:
            return client

    # Evict expired entries before adding
    if len(_pardot_clients) >= _MAX_PARDOT_CLIENTS:
        expired = [k for k, (_, t) in _pardot_clients.items() if (now - t) >= TOKEN_TTL_SECONDS]
        for k in expired:
            _close_pardot_http_client(_pardot_clients[k][0])
            del _pardot_clients[k]
        if len(_pardot_clients) >= _MAX_PARDOT_CLIENTS:
            oldest_key = min(_pardot_clients, key=lambda k: _pardot_clients[k][1])
            _close_pardot_http_client(_pardot_clients[oldest_key][0])
            del _pardot_clients[oldest_key]

    client = PardotClient(api_key=api_key)
    _pardot_clients[hk] = (client, now)
    return client


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

    _warn_large_result("pardot_get_prospects", len(prospects))
    truncated = len(prospects) > MAX_RESULT_RECORDS
    if truncated:
        prospects = prospects[:MAX_RESULT_RECORDS]
    result = {"count": len(prospects), "prospects": prospects, "_dataSource": "pardot"}
    if truncated:
        result["warning"] = f"Result truncated to {MAX_RESULT_RECORDS} records. Use filters to narrow your query."
    return result


async def pardot_get_prospect_by_email(
    email: Annotated[str, Field(description="Email address of the prospect to look up")],
) -> dict:
    """Get a single Pardot prospect by their email address."""
    client = get_pardot_client()
    result = await client.get("prospects", params={
        "fields": "id,email,firstName,lastName,score,campaignId,createdAt,updatedAt",
        "email": email,
    })
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
    pid = _validate_numeric_id(prospect_id, "prospect_id")
    _check_blocked_prospect_fields(fields)
    result = await client.patch(f"prospects/{pid}", json_body=fields)
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
    body = {"prospectId": _validate_numeric_id(prospect_id, "prospect_id"),
            "listId": _validate_numeric_id(list_id, "list_id")}
    result = await client.post("list-memberships", json_body=body)
    return {"success": True, "membership": result}


# ---------------------------------------------------------------------------
# Activity tools
# ---------------------------------------------------------------------------

# Pardot visitor activity type codes → (label, category)
ACTIVITY_TYPES: dict[int, tuple[str, str]] = {
    1:  ("Click", "web"),
    2:  ("View", "web"),
    3:  ("Error", "web"),
    4:  ("Success", "web"),
    5:  ("Session", "web"),
    6:  ("Email Sent", "email"),
    7:  ("Site Search", "web"),
    8:  ("Opportunity Created", "opportunity"),
    9:  ("Opportunity Won", "opportunity"),
    10: ("Opportunity Lost", "opportunity"),
    11: ("Email Open", "email"),
    12: ("Unsubscribe", "email"),
    13: ("Bounce", "email"),
    14: ("Spam Complaint", "email"),
    15: ("Email Preference", "email"),
    16: ("Opt In", "email"),
    17: ("Third Party Click", "email"),
    18: ("Opportunity Reopen", "opportunity"),
    19: ("Opportunity Linked", "opportunity"),
    20: ("Visit", "web"),
    21: ("Custom Redirect Click", "web"),
    35: ("Indirect Unsubscribe", "email"),
    36: ("Indirect Bounce", "email"),
    37: ("Indirect Opt In", "email"),
    38: ("Opportunity Unlinked", "opportunity"),
}

# Friendly name → type code (allows filtering by name instead of code)
ACTIVITY_TYPE_NAMES: dict[str, int] = {
    # Web
    "click": 1, "view": 2, "form_view": 2, "page_view": 2,
    "error": 3, "form_error": 3,
    "success": 4, "form_success": 4, "form_submit": 4,
    "session": 5, "site_search": 7, "visit": 20,
    "custom_redirect": 21,
    # Email
    "email_sent": 6, "email_open": 11, "unsubscribe": 12,
    "bounce": 13, "spam": 14, "email_preference": 15,
    "opt_in": 16, "third_party_click": 17,
    "indirect_unsubscribe": 35, "indirect_bounce": 36, "indirect_opt_in": 37,
    # Opportunity
    "opportunity_created": 8, "opportunity_won": 9, "opportunity_lost": 10,
    "opportunity_reopen": 18, "opportunity_linked": 19, "opportunity_unlinked": 38,
}


def _enrich_activity(activity: dict) -> dict:
    """Add activityLabel and category fields based on the numeric type code."""
    type_code = activity.get("type")
    if type_code is not None and type_code in ACTIVITY_TYPES:
        label, category = ACTIVITY_TYPES[type_code]
        activity["activityLabel"] = label
        activity["category"] = category
    return activity


async def pardot_get_visitor_activities(
    prospect_id: Annotated[str | None, Field(description="Filter by Pardot prospect ID")] = None,
    activity_type: Annotated[int | None, Field(
        description=(
            "Filter by numeric activity type code. "
            "Web: 1=Click, 2=View, 3=Error, 4=Success/FormSubmit, 5=Session, "
            "7=SiteSearch, 20=Visit, 21=CustomRedirect. "
            "Email: 6=Sent, 11=Open, 12=Unsubscribe, 13=Bounce, 14=Spam, "
            "15=Preference, 16=OptIn, 17=ThirdPartyClick. "
            "Opportunity: 8=Created, 9=Won, 10=Lost, 18=Reopen, 19=Linked."
        )
    )] = None,
    activity_type_name: Annotated[str | None, Field(
        description=(
            "Filter by friendly name instead of numeric code. "
            "Web: click, view, form_view, page_view, error, form_error, "
            "success, form_success, form_submit, session, site_search, visit, custom_redirect. "
            "Email: email_sent, email_open, unsubscribe, bounce, spam, "
            "email_preference, opt_in, third_party_click. "
            "Opportunity: opportunity_created, opportunity_won, opportunity_lost, "
            "opportunity_reopen, opportunity_linked, opportunity_unlinked."
        )
    )] = None,
    created_after: Annotated[str | None, Field(description="Only activities after this datetime (ISO 8601)")] = None,
    created_before: Annotated[str | None, Field(description="Only activities before this datetime (ISO 8601)")] = None,
) -> dict:
    """Get Pardot visitor activities with optional filters for prospect, type, and date range.

    Each activity is enriched with 'activityLabel' (human-readable name) and
    'category' (web / email / opportunity) for easier analysis.

    Use activity_type_name for friendly filtering (e.g. 'form_submit', 'email_open')
    or activity_type for the raw numeric code.
    """
    # Resolve friendly name to code (activity_type_name takes precedence if both given)
    resolved_type = activity_type
    if activity_type_name is not None:
        name_lower = activity_type_name.strip().lower()[:50]  # cap length before lookup
        if name_lower not in ACTIVITY_TYPE_NAMES:
            raise ToolError(
                f"Unknown activity_type_name: {name_lower!r}. "
                f"Valid names: {', '.join(sorted(ACTIVITY_TYPE_NAMES))}"
            )
        resolved_type = ACTIVITY_TYPE_NAMES[name_lower]

    client = get_pardot_client()
    params: dict[str, Any] = {
        "fields": "id,prospectId,type,typeName,details,campaignId,createdAt",
    }
    if prospect_id:
        _validate_numeric_id(prospect_id, "prospect_id")
        params["prospectId"] = prospect_id
    if resolved_type is not None:
        params["type"] = str(resolved_type)
    if created_after:
        params["createdAfter"] = created_after
    if created_before:
        params["createdBefore"] = created_before

    result = await client.get("visitor-activities", params=params)
    activities = [_enrich_activity(a) for a in result.get("values", [])]
    _warn_large_result("pardot_get_visitor_activities", len(activities))
    truncated = len(activities) > MAX_RESULT_RECORDS
    if truncated:
        activities = activities[:MAX_RESULT_RECORDS]
    output: dict[str, Any] = {"activities": activities, "_dataSource": "pardot"}
    if truncated:
        output["warning"] = f"Result truncated to {MAX_RESULT_RECORDS} records. Use filters to narrow your query."
    return output


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
    _validate_numeric_id(prospect_id, "prospect_id")
    client = get_pardot_client()
    # Pardot API v5 lifecycle-histories endpoint does NOT support prospectId
    # as a query parameter — only id and createdAt filters are available.
    # We fetch all records and filter client-side.
    result = await client.get(
        "lifecycle-histories",
        params={
            "fields": "id,prospectId,previousStageId,nextStageId,secondsInStage,createdAt",
        },
    )
    all_histories = result.get("values", [])
    # Client-side filter by prospect ID
    histories = [h for h in all_histories if str(h.get("prospectId", "")) == str(prospect_id)]
    return {"lifecycle_history": histories}


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
