"""
Salesforce CRM tools for the MCP server.

Provides SOQL queries, lead/contact CRUD, pipeline reporting, and activity
history via the simple-salesforce library. All tools are synchronous —
FastMCP runs them in a threadpool so they don't block the event loop.

Each user connects their own Salesforce org via MCP OAuth 2.1.
Tools automatically use the authenticated user's credentials and permissions.
"""

import os
import re
import time as _time
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

import httpx
from pydantic import Field
from simple_salesforce import Salesforce, SalesforceError
from fastmcp.exceptions import ToolError

from user_context import get_current_api_key
from token_store import get_token_store, _hash_key as _cache_key
from oauth import _validate_instance_url

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Salesforce client management (per-user via OAuth)
# ---------------------------------------------------------------------------

# Per-user cache: api_key -> (Salesforce client, created_monotonic)
_sf_clients: dict[str, tuple[Salesforce, float]] = {}
_CLIENT_TTL = 55 * 60  # 55 minutes
_MAX_CACHED_CLIENTS = 50  # max per-user clients in memory


def _get_oauth_sf_client(api_key: str) -> Salesforce:
    """Create or retrieve a cached per-user SF client using stored OAuth tokens."""
    store = get_token_store()
    tokens = store.get(api_key) if store else None

    if tokens is None:
        raise ToolError("No Salesforce tokens found for this session. Please reconnect via OAuth.")

    # Use HMAC-hashed key for cache (prevents raw token exposure in memory dumps)
    hk = _cache_key(api_key)

    # Check cache
    now = _time.monotonic()
    if hk in _sf_clients:
        client, created = _sf_clients[hk]
        if (now - created) < _CLIENT_TTL:
            return client

    # Evict expired entries before adding a new one
    if len(_sf_clients) >= _MAX_CACHED_CLIENTS:
        expired = [k for k, (_, t) in _sf_clients.items() if (now - t) >= _CLIENT_TTL]
        for k in expired:
            del _sf_clients[k]
        # If still at capacity, evict the oldest entry
        if len(_sf_clients) >= _MAX_CACHED_CLIENTS:
            oldest_key = min(_sf_clients, key=lambda k: _sf_clients[k][1])
            del _sf_clients[oldest_key]

    # Create new client from OAuth tokens
    try:
        client = Salesforce(
            instance_url=tokens["instance_url"],
            session_id=tokens["access_token"],
        )
        _sf_clients[hk] = (client, now)
        logger.info("Per-user SF client created (instance: %s)", tokens["instance_url"])
        return client
    except Exception as exc:
        raise ToolError(f"Salesforce client creation failed: {type(exc).__name__}")


def get_sf_client() -> Salesforce:
    """
    Get the Salesforce client for the current request.

    Uses the authenticated user's OAuth tokens to create a per-user client.
    """
    api_key = get_current_api_key()
    if not api_key:
        raise ToolError("No authenticated session. Please connect via MCP OAuth.")
    return _get_oauth_sf_client(api_key)


def reset_sf_client() -> None:
    """Force re-initialization on next call (e.g. after session expiry)."""
    api_key = get_current_api_key()
    if api_key:
        hk = _cache_key(api_key)
        if hk in _sf_clients:
            del _sf_clients[hk]


def _refresh_oauth_token(tokens: dict) -> dict | None:
    """Synchronously refresh an OAuth token using the refresh_token grant."""
    try:
        login_url = os.environ.get("SF_OAUTH_LOGIN_URL", "https://login.salesforce.com")
        resp = httpx.post(
            f"{login_url}/services/oauth2/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": os.environ.get("SF_OAUTH_CLIENT_ID", ""),
                "client_secret": os.environ.get("SF_OAUTH_CLIENT_SECRET", ""),
            },
        )
        if resp.status_code == 200:
            data = resp.json()
            new_instance_url = data.get("instance_url", tokens["instance_url"])
            if not _validate_instance_url(new_instance_url):
                logger.warning("OAuth refresh returned invalid instance_url: %s", new_instance_url[:50])
                new_instance_url = tokens["instance_url"]
            import time
            return {
                "access_token": data["access_token"],
                "refresh_token": tokens["refresh_token"],  # SF doesn't rotate refresh tokens
                "instance_url": new_instance_url,
                "issued_at": time.time(),
                "pardot_business_unit_id": tokens.get("pardot_business_unit_id"),
            }
    except Exception as e:
        logger.error("OAuth token refresh failed: %s", type(e).__name__)
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Anomaly detection & output sanitization
# ---------------------------------------------------------------------------

LARGE_RESULT_THRESHOLD = 1000
MAX_RESULT_RECORDS = 500


def _warn_large_result(tool_name: str, total_size: int) -> None:
    """Log a warning if a query returned an unusually large result set."""
    if total_size > LARGE_RESULT_THRESHOLD:
        logger.warning(
            "Large result set from %s: %d records returned (threshold: %d)",
            tool_name, total_size, LARGE_RESULT_THRESHOLD,
        )


def _sanitize_result(records: list, total_size: int, tool_name: str) -> dict:
    """Truncate large result sets and add data-source markers."""
    truncated = len(records) > MAX_RESULT_RECORDS
    if truncated:
        records = records[:MAX_RESULT_RECORDS]

    result = {
        "totalSize": total_size,
        "returnedSize": len(records),
        "records": records,
        "_dataSource": "salesforce",
    }
    if truncated:
        result["warning"] = (
            f"Result truncated: showing {MAX_RESULT_RECORDS} of {total_size} records. "
            "Refine your query with additional filters to see specific records."
        )
    return result


def _escape_soql(value: str) -> str:
    """Escape a string value for safe inclusion in a SOQL WHERE clause."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$")


def _validate_date(value: str) -> None:
    """Ensure value matches YYYY-MM-DD format."""
    if not _DATE_RE.match(value):
        raise ToolError(f"Invalid date format (expected YYYY-MM-DD): {value!r}")


def _validate_datetime(value: str) -> None:
    """Ensure value matches ISO 8601 datetime format."""
    if not _DATETIME_RE.match(value):
        raise ToolError(f"Invalid datetime format (expected ISO 8601): {value!r}")


def _validate_select_only(soql: str) -> None:
    """Ensure the SOQL string is a SELECT query (read-only enforcement)."""
    normalized = soql.strip().upper()
    if not normalized.startswith("SELECT"):
        raise ToolError("Only SELECT queries are allowed via sf_query")


# Sensitive fields that cannot be changed through update/create tools (lowercase for case-insensitive check)
BLOCKED_LEAD_FIELDS: frozenset[str] = frozenset(
    {"ownerid", "isconverted", "isdeleted", "masterrecordid"}
)
BLOCKED_CONTACT_FIELDS: frozenset[str] = frozenset(
    {"ownerid", "isdeleted", "masterrecordid"}
)


def _check_blocked_fields(fields: dict, blocked: frozenset[str], object_name: str) -> None:
    """Raise ToolError if any field key is in the blocked set (case-insensitive)."""
    found = {k for k in fields if k.lower() in blocked}
    if found:
        raise ToolError(f"Cannot update protected {object_name} fields: {found}")


def _safe_error(text: str, max_len: int = 200) -> str:
    """Truncate error response text to prevent leaking org details."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "... [truncated]"


def _safe_query(sf: Salesforce, soql: str) -> dict:
    """Execute a SOQL query with automatic session-expiry recovery."""
    try:
        return sf.query_all(soql)
    except SalesforceError as exc:
        if "INVALID_SESSION_ID" in str(exc):
            logger.warning("SF session expired — attempting refresh")
            api_key = get_current_api_key()
            store = get_token_store()
            if api_key and store:
                tokens = store.get(api_key)
                if tokens and tokens.get("refresh_token"):
                    new_tokens = _refresh_oauth_token(tokens)
                    if new_tokens:
                        store.put(api_key, new_tokens)
            reset_sf_client()
            sf = get_sf_client()
            return sf.query_all(soql)
        raise


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def sf_query(
    soql: Annotated[str, Field(description="SOQL query to execute against Salesforce")],
) -> dict:
    """Run an arbitrary SOQL query against Salesforce and return all matching records."""
    _validate_select_only(soql)
    sf = get_sf_client()
    try:
        result = _safe_query(sf, soql)
        _warn_large_result("sf_query", result["totalSize"])
        return _sanitize_result(result["records"], result["totalSize"], "sf_query")
    except SalesforceError as exc:
        raise ToolError(f"SOQL query failed: {_safe_error(str(exc))}")


def sf_get_leads(
    status: Annotated[str | None, Field(description="Filter by Lead Status (e.g. 'Open - Not Contacted', 'Working')")] = None,
    days_created: Annotated[int | None, Field(description="Only return leads created in the last N days", ge=1)] = None,
    lead_source: Annotated[str | None, Field(description="Filter by LeadSource field (e.g. 'Web', 'Referral')")] = None,
) -> dict:
    """Get Salesforce leads with optional filters for status, creation recency, and lead source."""
    sf = get_sf_client()
    conditions: list[str] = []

    if status:
        conditions.append(f"Status = '{_escape_soql(status)}'")
    if days_created is not None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days_created)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        conditions.append(f"CreatedDate >= {cutoff}")
    if lead_source:
        conditions.append(f"LeadSource = '{_escape_soql(lead_source)}'")

    soql = (
        "SELECT Id, FirstName, LastName, Email, Company, Status, "
        "LeadSource, Phone, CreatedDate "
        "FROM Lead"
    )
    if conditions:
        soql += " WHERE " + " AND ".join(conditions)
    soql += " ORDER BY CreatedDate DESC LIMIT 200"

    try:
        result = _safe_query(sf, soql)
        _warn_large_result("sf_get_leads", result["totalSize"])
        return _sanitize_result(result["records"], result["totalSize"], "sf_get_leads")
    except SalesforceError as exc:
        raise ToolError(f"Failed to get leads: {_safe_error(str(exc))}")


def sf_get_contacts(
    name: Annotated[str | None, Field(description="Search by contact name (partial match)")] = None,
    email: Annotated[str | None, Field(description="Filter by exact email address")] = None,
    account_id: Annotated[str | None, Field(description="Filter by Salesforce Account ID")] = None,
) -> dict:
    """Get Salesforce contacts with optional filters for name, email, and account."""
    sf = get_sf_client()
    conditions: list[str] = []

    if name:
        conditions.append(f"Name LIKE '%{_escape_soql(name)}%'")
    if email:
        conditions.append(f"Email = '{_escape_soql(email)}'")
    if account_id:
        conditions.append(f"AccountId = '{_escape_soql(account_id)}'")

    soql = (
        "SELECT Id, FirstName, LastName, Email, Phone, Title, "
        "AccountId, Account.Name "
        "FROM Contact"
    )
    if conditions:
        soql += " WHERE " + " AND ".join(conditions)
    soql += " ORDER BY LastName ASC LIMIT 200"

    try:
        result = _safe_query(sf, soql)
        _warn_large_result("sf_get_contacts", result["totalSize"])
        return _sanitize_result(result["records"], result["totalSize"], "sf_get_contacts")
    except SalesforceError as exc:
        raise ToolError(f"Failed to get contacts: {_safe_error(str(exc))}")


def sf_update_lead(
    lead_id: Annotated[str, Field(description="Salesforce Lead ID (15 or 18 character)")],
    fields: Annotated[
        dict,
        Field(
            description=(
                "Dictionary of field names and new values to update, "
                "e.g. {'Status': 'Contacted', 'Company': 'Acme Inc.'}"
            )
        ),
    ],
) -> dict:
    """Update a Salesforce lead by ID with the given field values."""
    sf = get_sf_client()
    if not lead_id or not fields:
        raise ToolError("Both lead_id and fields are required")
    _check_blocked_fields(fields, BLOCKED_LEAD_FIELDS, "Lead")
    try:
        sf.Lead.update(lead_id, fields)
        return {
            "success": True,
            "lead_id": lead_id,
            "updated_fields": list(fields.keys()),
        }
    except SalesforceError as exc:
        raise ToolError(f"Failed to update lead {lead_id}: {_safe_error(str(exc))}")


def sf_update_contact(
    contact_id: Annotated[str, Field(description="Salesforce Contact ID (15 or 18 character)")],
    fields: Annotated[
        dict,
        Field(description="Dictionary of field names and new values to update"),
    ],
) -> dict:
    """Update a Salesforce contact by ID with the given field values."""
    sf = get_sf_client()
    if not contact_id or not fields:
        raise ToolError("Both contact_id and fields are required")
    _check_blocked_fields(fields, BLOCKED_CONTACT_FIELDS, "Contact")
    try:
        sf.Contact.update(contact_id, fields)
        return {
            "success": True,
            "contact_id": contact_id,
            "updated_fields": list(fields.keys()),
        }
    except SalesforceError as exc:
        raise ToolError(f"Failed to update contact {contact_id}: {_safe_error(str(exc))}")


def sf_create_lead(
    fields: Annotated[
        dict,
        Field(
            description=(
                "Dictionary of field names and values for the new lead. "
                "'LastName' and 'Company' are required by Salesforce."
            )
        ),
    ],
) -> dict:
    """Create a new lead in Salesforce. At minimum, LastName and Company are required."""
    sf = get_sf_client()
    if "LastName" not in fields or "Company" not in fields:
        raise ToolError("fields must include 'LastName' and 'Company' at minimum")
    _check_blocked_fields(fields, BLOCKED_LEAD_FIELDS, "Lead")
    try:
        result = sf.Lead.create(fields)
        return {
            "success": result.get("success", False),
            "id": result.get("id"),
            "errors": result.get("errors", []),
        }
    except SalesforceError as exc:
        raise ToolError(f"Failed to create lead: {_safe_error(str(exc))}")


def sf_pipeline_report(
    owner_id: Annotated[
        str | None,
        Field(description="Filter by Opportunity Owner ID. Omit for all owners."),
    ] = None,
) -> dict:
    """
    Generate a pipeline report: open Opportunities aggregated by StageName.
    Returns the count and total amount per stage.
    """
    sf = get_sf_client()
    soql = (
        "SELECT StageName, COUNT(Id) cnt, SUM(Amount) total_amount "
        "FROM Opportunity "
        "WHERE IsClosed = false"
    )
    if owner_id:
        soql += f" AND OwnerId = '{_escape_soql(owner_id)}'"
    soql += " GROUP BY StageName ORDER BY StageName"

    try:
        result = sf.query(soql)
        stages = [
            {
                "stage": rec["StageName"],
                "count": rec["cnt"],
                "total_amount": rec["total_amount"] or 0,
            }
            for rec in result["records"]
        ]
        return {"stages": stages}
    except SalesforceError as exc:
        raise ToolError(f"Pipeline report failed: {_safe_error(str(exc))}")


# ---------------------------------------------------------------------------
# Activity tools
# ---------------------------------------------------------------------------


def sf_get_tasks(
    who_id: Annotated[str | None, Field(description="Filter by WhoId (Lead or Contact ID)")] = None,
    what_id: Annotated[str | None, Field(description="Filter by WhatId (Account, Opportunity, etc.)")] = None,
    status: Annotated[str | None, Field(description="Filter by Status (e.g. 'Completed', 'Not Started')")] = None,
    activity_date_from: Annotated[str | None, Field(description="Start date filter (YYYY-MM-DD format)")] = None,
    activity_date_to: Annotated[str | None, Field(description="End date filter (YYYY-MM-DD format)")] = None,
    subject_search: Annotated[str | None, Field(description="Search Subject field (partial match)")] = None,
) -> dict:
    """Get Salesforce tasks with optional filters for related record, status, date range, and subject."""
    sf = get_sf_client()
    conditions: list[str] = []

    if who_id:
        conditions.append(f"WhoId = '{_escape_soql(who_id)}'")
    if what_id:
        conditions.append(f"WhatId = '{_escape_soql(what_id)}'")
    if status:
        conditions.append(f"Status = '{_escape_soql(status)}'")
    if activity_date_from:
        _validate_date(activity_date_from)
        conditions.append(f"ActivityDate >= {activity_date_from}")
    if activity_date_to:
        _validate_date(activity_date_to)
        conditions.append(f"ActivityDate <= {activity_date_to}")
    if subject_search:
        conditions.append(f"Subject LIKE '%{_escape_soql(subject_search)}%'")

    soql = (
        "SELECT Id, Subject, Description, Status, Priority, "
        "ActivityDate, WhoId, WhatId, CreatedDate "
        "FROM Task"
    )
    if conditions:
        soql += " WHERE " + " AND ".join(conditions)
    soql += " ORDER BY ActivityDate DESC LIMIT 200"

    try:
        result = _safe_query(sf, soql)
        _warn_large_result("sf_get_tasks", result["totalSize"])
        return _sanitize_result(result["records"], result["totalSize"], "sf_get_tasks")
    except SalesforceError as exc:
        raise ToolError(f"Failed to get tasks: {_safe_error(str(exc))}")


def sf_get_events(
    who_id: Annotated[str | None, Field(description="Filter by WhoId (Lead or Contact ID)")] = None,
    what_id: Annotated[str | None, Field(description="Filter by WhatId (Account, Opportunity, etc.)")] = None,
    start_from: Annotated[str | None, Field(description="Start datetime filter (ISO 8601, e.g. 2024-01-15T00:00:00Z)")] = None,
    start_to: Annotated[str | None, Field(description="End datetime filter (ISO 8601, e.g. 2024-02-15T23:59:59Z)")] = None,
) -> dict:
    """Get Salesforce events with optional filters for related record and datetime range."""
    sf = get_sf_client()
    conditions: list[str] = []

    if who_id:
        conditions.append(f"WhoId = '{_escape_soql(who_id)}'")
    if what_id:
        conditions.append(f"WhatId = '{_escape_soql(what_id)}'")
    if start_from:
        _validate_datetime(start_from)
        conditions.append(f"StartDateTime >= {start_from}")
    if start_to:
        _validate_datetime(start_to)
        conditions.append(f"StartDateTime <= {start_to}")

    soql = (
        "SELECT Id, Subject, Description, StartDateTime, EndDateTime, "
        "WhoId, WhatId, Location, CreatedDate "
        "FROM Event"
    )
    if conditions:
        soql += " WHERE " + " AND ".join(conditions)
    soql += " ORDER BY StartDateTime DESC LIMIT 200"

    try:
        result = _safe_query(sf, soql)
        _warn_large_result("sf_get_events", result["totalSize"])
        return _sanitize_result(result["records"], result["totalSize"], "sf_get_events")
    except SalesforceError as exc:
        raise ToolError(f"Failed to get events: {_safe_error(str(exc))}")


def sf_get_activity_history(
    record_id: Annotated[str, Field(description="Salesforce record ID (Lead, Contact, or Account)")],
    days: Annotated[int, Field(description="Look back N days from today", ge=1)] = 90,
) -> dict:
    """Get combined tasks and events for a specific record, sorted by date (most recent first)."""
    sf = get_sf_client()
    escaped_id = _escape_soql(record_id)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    task_soql = (
        "SELECT Id, Subject, Description, Status, Priority, "
        "ActivityDate, WhoId, WhatId, CreatedDate "
        f"FROM Task WHERE (WhoId = '{escaped_id}' OR WhatId = '{escaped_id}') "
        f"AND CreatedDate >= {cutoff} "
        "ORDER BY ActivityDate DESC LIMIT 100"
    )

    event_soql = (
        "SELECT Id, Subject, Description, StartDateTime, EndDateTime, "
        "WhoId, WhatId, Location, CreatedDate "
        f"FROM Event WHERE (WhoId = '{escaped_id}' OR WhatId = '{escaped_id}') "
        f"AND CreatedDate >= {cutoff} "
        "ORDER BY StartDateTime DESC LIMIT 100"
    )

    try:
        task_result = _safe_query(sf, task_soql)
        event_result = _safe_query(sf, event_soql)

        tasks = [
            {**r, "activity_type": "Task", "sort_date": r.get("ActivityDate") or r.get("CreatedDate")}
            for r in task_result["records"]
        ]
        events = [
            {**r, "activity_type": "Event", "sort_date": r.get("StartDateTime") or r.get("CreatedDate")}
            for r in event_result["records"]
        ]

        combined = sorted(tasks + events, key=lambda r: r.get("sort_date", ""), reverse=True)

        total = task_result["totalSize"] + event_result["totalSize"]
        _warn_large_result("sf_get_activity_history", total)

        truncated = len(combined) > MAX_RESULT_RECORDS
        if truncated:
            combined = combined[:MAX_RESULT_RECORDS]

        result = {
            "record_id": record_id,
            "task_count": task_result["totalSize"],
            "event_count": event_result["totalSize"],
            "total_count": total,
            "activities": combined,
            "_dataSource": "salesforce",
        }
        if truncated:
            result["warning"] = f"Activities truncated to {MAX_RESULT_RECORDS} records."
        return result
    except SalesforceError as exc:
        raise ToolError(f"Failed to get activity history: {_safe_error(str(exc))}")
