"""
Shared Salesforce OAuth utilities.

Configuration constants, instance URL validation, and Pardot Business Unit
auto-detection.  Used by mcp_oauth.py (MCP OAuth 2.1 flow).
"""

import os
import logging
import urllib.parse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed Salesforce instance URL suffixes
# ---------------------------------------------------------------------------

_ALLOWED_SF_DOMAINS = (
    ".salesforce.com",
    ".force.com",
    ".salesforce.mil",
    ".cloudforce.com",
)


def _validate_instance_url(url: str) -> bool:
    """Check that instance_url is a valid Salesforce domain over HTTPS."""
    if not url.startswith("https://"):
        return False
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return False
    return any(host.endswith(d) for d in _ALLOWED_SF_DOMAINS)


# ---------------------------------------------------------------------------
# OAuth configuration from env vars
# ---------------------------------------------------------------------------

SF_OAUTH_CLIENT_ID = os.environ.get("SF_OAUTH_CLIENT_ID", "")
SF_OAUTH_CLIENT_SECRET = os.environ.get("SF_OAUTH_CLIENT_SECRET", "")
SF_OAUTH_REDIRECT_URI = os.environ.get("SF_OAUTH_REDIRECT_URI", "")
SF_OAUTH_LOGIN_URL = os.environ.get("SF_OAUTH_LOGIN_URL", "https://login.salesforce.com")

# Salesforce API version for REST calls
_SF_API_VERSION = "v59.0"


def _validate_oauth_env_vars() -> None:
    """Fail fast if required OAuth environment variables are missing or empty."""
    missing = []
    if not SF_OAUTH_CLIENT_ID:
        missing.append("SF_OAUTH_CLIENT_ID")
    if not SF_OAUTH_CLIENT_SECRET:
        missing.append("SF_OAUTH_CLIENT_SECRET")
    if missing:
        raise RuntimeError(
            f"Required OAuth environment variables are not set: {', '.join(missing)}. "
            "Copy .env.example to .env and fill in your Connected App credentials."
        )


async def detect_pardot_business_unit_id(
    access_token: str, instance_url: str
) -> str | None:
    """
    Auto-detect the Pardot Business Unit ID by querying the PardotTenant
    object via the Salesforce Tooling API (not standard SOQL — PardotTenant
    is a Tooling API object, available since API v56.0).

    Returns the ID (format 0Uv...) or None if Pardot is not provisioned,
    permissions are insufficient, or the query fails.
    """
    soql = "SELECT Id, PardotTenantName FROM PardotTenant LIMIT 1"
    url = f"{instance_url}/services/data/{_SF_API_VERSION}/tooling/query"
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}

    logger.info("Detecting Pardot BUID via Tooling API: %s", url)
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers, params={"q": soql})
            if resp.status_code == 200:
                data = resp.json()
                records = data.get("records", [])
                if records:
                    buid = records[0].get("Id", "")
                    name = records[0].get("PardotTenantName", "")
                    if buid.startswith("0Uv"):
                        logger.info(
                            "Auto-detected Pardot Business Unit ID: %s (%s)",
                            buid, name,
                        )
                        return buid
                    logger.warning("PardotTenant record ID has unexpected prefix: %s", buid[:6])
                    return buid  # return anyway, might still work
                logger.info("No PardotTenant records found — Pardot may not be provisioned")
            else:
                logger.warning(
                    "PardotTenant Tooling API query failed (HTTP %d) — "
                    "Use pardot_set_business_unit tool to set manually",
                    resp.status_code,
                )
    except Exception as exc:
        logger.warning(
            "Failed to auto-detect Pardot Business Unit ID: %s",
            type(exc).__name__,
        )

    return None
