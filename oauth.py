"""
Self-service Salesforce OAuth 2.0 Web Server Flow.

Users visit /login in a browser, authenticate with their own Salesforce org,
and receive a session token to paste into Claude Desktop.  No admin-generated
API keys required.

GET  /login           — Redirect to Salesforce OAuth authorize URL (no auth)
GET  /oauth/callback  — Exchange authorization code, generate session token,
                         show HTML page with token + instructions
GET  /oauth/status    — Check connection status (Bearer session_token)
POST /oauth/revoke    — Remove session token (Bearer session_token)
"""

import hashlib
import html
import os
import time
import logging
import secrets
import urllib.parse

import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from token_store import get_token_store, UserTokens

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


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OAuth configuration from env vars
# ---------------------------------------------------------------------------

SF_OAUTH_CLIENT_ID = os.environ.get("SF_OAUTH_CLIENT_ID", "")
SF_OAUTH_CLIENT_SECRET = os.environ.get("SF_OAUTH_CLIENT_SECRET", "")
SF_OAUTH_REDIRECT_URI = os.environ.get("SF_OAUTH_REDIRECT_URI", "")
SF_OAUTH_LOGIN_URL = os.environ.get("SF_OAUTH_LOGIN_URL", "https://login.salesforce.com")

# Salesforce API version for REST calls
_SF_API_VERSION = "v59.0"


async def detect_pardot_business_unit_id(
    access_token: str, instance_url: str
) -> str | None:
    """
    Auto-detect the Pardot Business Unit ID by querying the PardotTenant
    sObject in Salesforce. Returns the ID (format 0Uv...) or None if
    Pardot is not provisioned or the query fails.
    """
    soql = "SELECT Id FROM PardotTenant WHERE IsDeleted = false LIMIT 1"
    url = f"{instance_url}/services/data/{_SF_API_VERSION}/query"
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers, params={"q": soql})
            if resp.status_code == 200:
                data = resp.json()
                records = data.get("records", [])
                if records:
                    buid = records[0].get("Id", "")
                    if buid.startswith("0Uv"):
                        logger.info("Auto-detected Pardot Business Unit ID: %s", buid)
                        return buid
                    logger.warning("PardotTenant record ID has unexpected prefix: %s", buid[:6])
                    return buid  # return anyway, might still work
                logger.info("No PardotTenant records found — Pardot may not be provisioned")
            else:
                logger.warning(
                    "PardotTenant query failed (HTTP %d): %s",
                    resp.status_code,
                    resp.text[:200],
                )
    except Exception as exc:
        logger.warning("Failed to auto-detect Pardot Business Unit ID: %s", exc)

    return None

# ---------------------------------------------------------------------------
# CSRF protection: state -> created_at (no api_key mapping needed anymore)
# ---------------------------------------------------------------------------

_STATE_TTL_SECONDS = 600  # 10 minutes
_MAX_PENDING_STATES = 100

_pending_states: dict[str, float] = {}


def _cleanup_expired_states() -> None:
    """Remove expired pending states to prevent memory leak."""
    now = time.time()
    expired = [s for s, ts in _pending_states.items() if now - ts > _STATE_TTL_SECONDS]
    for s in expired:
        del _pending_states[s]


def _token_fingerprint(token: str) -> str:
    """Return first 8 hex chars of SHA-256 hash (for safe logging)."""
    return hashlib.sha256(token.encode()).hexdigest()[:8]


def _extract_session_token(request: Request) -> str | None:
    """Extract Bearer token from Authorization header (no validation)."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None
    return auth_header.split(" ", 1)[1]


# ---------------------------------------------------------------------------
# /login — redirect to Salesforce OAuth (NO auth required)
# ---------------------------------------------------------------------------


async def oauth_login(request: Request) -> RedirectResponse:
    """Redirect the user to Salesforce OAuth authorize URL."""
    if not SF_OAUTH_CLIENT_ID or not SF_OAUTH_REDIRECT_URI:
        return JSONResponse(
            {"error": "OAuth not configured (SF_OAUTH_CLIENT_ID / SF_OAUTH_REDIRECT_URI missing)"},
            status_code=503,
        )

    _cleanup_expired_states()

    if len(_pending_states) >= _MAX_PENDING_STATES:
        return JSONResponse(
            {"error": "Too many pending authorization requests, try again later"},
            status_code=429,
        )

    state = secrets.token_urlsafe(32)
    _pending_states[state] = time.time()

    params = {
        "response_type": "code",
        "client_id": SF_OAUTH_CLIENT_ID,
        "redirect_uri": SF_OAUTH_REDIRECT_URI,
        "state": state,
        "scope": "api refresh_token pardot_api",
    }
    authorize_url = f"{SF_OAUTH_LOGIN_URL}/services/oauth2/authorize?{urllib.parse.urlencode(params)}"

    return RedirectResponse(url=authorize_url)


# ---------------------------------------------------------------------------
# /oauth/callback — exchange code for tokens, return HTML with session_token
# ---------------------------------------------------------------------------

_SUCCESS_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connected to Salesforce</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f5f5f5; display: flex; justify-content: center; align-items: center;
           min-height: 100vh; padding: 20px; }}
    .card {{ background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1);
             max-width: 640px; width: 100%; padding: 40px; }}
    h1 {{ color: #1a1a1a; font-size: 24px; margin-bottom: 8px; }}
    .subtitle {{ color: #666; margin-bottom: 24px; }}
    .step {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px;
             padding: 20px; margin-bottom: 16px; }}
    .step-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }}
    .step-number {{ background: #0070d2; color: white; width: 28px; height: 28px;
                     border-radius: 50%; display: flex; align-items: center; justify-content: center;
                     font-size: 14px; font-weight: 600; flex-shrink: 0; }}
    .step-title {{ font-size: 16px; font-weight: 600; color: #1a1a1a; }}
    .step-desc {{ color: #555; font-size: 14px; line-height: 1.5; margin-left: 40px; }}
    .btn {{ border: none; border-radius: 8px; padding: 12px 24px; font-size: 15px;
             cursor: pointer; width: 100%; font-weight: 600; transition: all 0.2s; }}
    .btn-primary {{ background: #0070d2; color: white; }}
    .btn-primary:hover {{ background: #005bb5; }}
    .btn-secondary {{ background: #f0f4f8; color: #0070d2; border: 2px solid #0070d2;
                       margin-top: 8px; }}
    .btn-secondary:hover {{ background: #e8eef4; }}
    .btn.done {{ background: #2e844a; color: white; border-color: #2e844a; }}
    .path-box {{ background: #f0f4f8; border: 1px solid #d0d7de; border-radius: 6px;
                  padding: 10px 14px; margin: 8px 0; font-family: 'SF Mono', Monaco, Consolas, monospace;
                  font-size: 12px; color: #333; word-break: break-all; }}
    .os-tabs {{ display: flex; gap: 0; margin: 8px 0 4px 0; }}
    .os-tab {{ padding: 6px 16px; font-size: 13px; cursor: pointer; background: #e2e8f0;
                color: #555; border: none; font-weight: 500; }}
    .os-tab:first-child {{ border-radius: 6px 0 0 6px; }}
    .os-tab:last-child {{ border-radius: 0 6px 6px 0; }}
    .os-tab.active {{ background: #0070d2; color: white; }}
    .hidden {{ display: none; }}
    .token-box {{ background: #f0f4f8; border: 1px solid #d0d7de; border-radius: 8px;
                   padding: 16px; margin: 12px 0; }}
    .token-label {{ font-size: 12px; color: #666; text-transform: uppercase;
                     letter-spacing: 0.5px; margin-bottom: 8px; }}
    .token-value {{ font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 13px;
                     word-break: break-all; color: #1a1a1a; user-select: all; }}
    .config-block {{ background: #1e1e1e; color: #d4d4d4; border-radius: 8px;
                      padding: 16px; margin: 12px 0; font-family: 'SF Mono', Monaco, Consolas, monospace;
                      font-size: 12px; overflow-x: auto; white-space: pre; }}
    .divider {{ border-top: 1px solid #e2e8f0; margin: 24px 0; }}
    .instance {{ color: #666; font-size: 13px; margin-top: 16px; }}
    .collapsible {{ cursor: pointer; color: #0070d2; font-size: 13px; margin-top: 12px;
                     display: inline-block; }}
    .collapsible:hover {{ text-decoration: underline; }}
    .expire-note {{ color: #888; font-size: 12px; margin-top: 12px; line-height: 1.4; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Connected to Salesforce</h1>
    <p class="subtitle">Follow these 3 steps to connect Claude Desktop to your Salesforce.</p>

    <!-- Step 1: Download -->
    <div class="step">
      <div class="step-header">
        <div class="step-number">1</div>
        <div class="step-title">Download config file</div>
      </div>
      <div class="step-desc">
        Click the button below to download the ready-made configuration file.
      </div>
      <br>
      <button class="btn btn-primary" id="downloadBtn" onclick="downloadConfig()">Download claude_desktop_config.json</button>
    </div>

    <!-- Step 2: Place file -->
    <div class="step">
      <div class="step-header">
        <div class="step-number">2</div>
        <div class="step-title">Place the file in the right folder</div>
      </div>
      <div class="step-desc">
        Move the downloaded file to this folder (replace if it already exists):
        <div class="os-tabs">
          <button class="os-tab active" onclick="showOS('mac')">macOS</button>
          <button class="os-tab" onclick="showOS('win')">Windows</button>
        </div>
        <div class="path-box" id="path-mac">~/Library/Application Support/Claude/</div>
        <div class="path-box hidden" id="path-win">%APPDATA%\\Claude\\</div>
        <button class="btn btn-secondary" onclick="copyPath()">Copy folder path</button>
      </div>
    </div>

    <!-- Step 3: Restart -->
    <div class="step">
      <div class="step-header">
        <div class="step-number">3</div>
        <div class="step-title">Restart Claude Desktop</div>
      </div>
      <div class="step-desc">
        Fully close Claude Desktop and reopen it. You should see a hammer icon in the chat
        &mdash; that means Salesforce tools are connected.
      </div>
    </div>

    <p class="expire-note">
      Your session token expires in 24 hours. After that, visit this login page again
      to get a new config file.
    </p>

    <div class="divider"></div>

    <!-- Advanced: manual setup -->
    <span class="collapsible" onclick="toggleAdvanced()">Advanced: manual setup &darr;</span>
    <div id="advanced" class="hidden" style="margin-top: 12px;">
      <div class="token-box">
        <div class="token-label">Session Token</div>
        <div class="token-value" id="token">{session_token}</div>
      </div>
      <button class="btn btn-secondary" onclick="copyToken()">Copy Token</button>
      <p style="margin-top:12px; font-size:13px; color:#555;">
        Or copy the full config and paste it into
        <strong>Claude Desktop &rarr; Settings &rarr; Developer &rarr; Edit Config</strong>:
      </p>
      <div class="config-block">{{
  "mcpServers": {{
    "salesforce": {{
      "url": "{server_url}/sse",
      "headers": {{
        "Authorization": "Bearer {session_token}"
      }}
    }}
  }}
}}</div>
      <button class="btn btn-secondary" onclick="copyConfig()">Copy Config JSON</button>
    </div>

    <p class="instance">Connected org: <strong>{instance_url}</strong></p>
  </div>

  <script>
    const CONFIG_JSON = JSON.stringify({{
      "mcpServers": {{
        "salesforce": {{
          "url": "{server_url}/sse",
          "headers": {{
            "Authorization": "Bearer {session_token}"
          }}
        }}
      }}
    }}, null, 2);

    let currentOS = 'mac';

    function downloadConfig() {{
      const blob = new Blob([CONFIG_JSON], {{ type: 'application/json' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'claude_desktop_config.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      const btn = document.getElementById('downloadBtn');
      btn.textContent = 'Downloaded!';
      btn.classList.add('done');
      setTimeout(() => {{ btn.textContent = 'Download claude_desktop_config.json'; btn.classList.remove('done'); }}, 2000);
    }}

    function showOS(os) {{
      currentOS = os;
      document.querySelectorAll('.os-tab').forEach(t => t.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('path-mac').classList.toggle('hidden', os !== 'mac');
      document.getElementById('path-win').classList.toggle('hidden', os !== 'win');
    }}

    function copyPath() {{
      const path = currentOS === 'mac'
        ? '~/Library/Application Support/Claude/'
        : '%APPDATA%\\\\Claude\\\\';
      navigator.clipboard.writeText(path).then(() => {{
        event.target.textContent = 'Copied!';
        event.target.classList.add('done');
        setTimeout(() => {{ event.target.textContent = 'Copy folder path'; event.target.classList.remove('done'); }}, 2000);
      }});
    }}

    function copyToken() {{
      const token = document.getElementById('token').textContent;
      navigator.clipboard.writeText(token).then(() => {{
        event.target.textContent = 'Copied!';
        event.target.classList.add('done');
        setTimeout(() => {{ event.target.textContent = 'Copy Token'; event.target.classList.remove('done'); }}, 2000);
      }});
    }}

    function copyConfig() {{
      navigator.clipboard.writeText(CONFIG_JSON).then(() => {{
        event.target.textContent = 'Copied!';
        event.target.classList.add('done');
        setTimeout(() => {{ event.target.textContent = 'Copy Config JSON'; event.target.classList.remove('done'); }}, 2000);
      }});
    }}

    function toggleAdvanced() {{
      const el = document.getElementById('advanced');
      el.classList.toggle('hidden');
      event.target.innerHTML = el.classList.contains('hidden')
        ? 'Advanced: manual setup &darr;'
        : 'Advanced: manual setup &uarr;';
    }}
  </script>
</body>
</html>
"""

_ERROR_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connection Failed</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f5f5f5; display: flex; justify-content: center; align-items: center;
           min-height: 100vh; padding: 20px; }}
    .card {{ background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1);
             max-width: 500px; width: 100%; padding: 40px; text-align: center; }}
    h1 {{ color: #c23934; font-size: 24px; margin-bottom: 12px; }}
    p {{ color: #666; line-height: 1.5; }}
    a {{ color: #0070d2; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Connection Failed</h1>
    <p>{error_message}</p>
    <p style="margin-top: 16px;"><a href="/login">Try again</a></p>
  </div>
</body>
</html>
"""


async def oauth_callback(request: Request) -> HTMLResponse:
    """Handle OAuth callback: exchange code, generate session_token, show HTML."""
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code or not state:
        return HTMLResponse(
            _ERROR_HTML.format(error_message="Missing authorization code. Please try again."),
            status_code=400,
        )

    created_at = _pending_states.pop(state, None)
    if created_at is None:
        return HTMLResponse(
            _ERROR_HTML.format(error_message="Invalid or expired session. Please try again."),
            status_code=400,
        )

    if time.time() - created_at > _STATE_TTL_SECONDS:
        return HTMLResponse(
            _ERROR_HTML.format(error_message="Session expired. Please try again."),
            status_code=400,
        )

    store = get_token_store()
    if not store:
        return HTMLResponse(
            _ERROR_HTML.format(error_message="Server misconfigured: ENCRYPTION_KEY not set."),
            status_code=503,
        )

    # Exchange authorization code for tokens
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SF_OAUTH_LOGIN_URL}/services/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": SF_OAUTH_CLIENT_ID,
                "client_secret": SF_OAUTH_CLIENT_SECRET,
                "redirect_uri": SF_OAUTH_REDIRECT_URI,
            },
        )
        if resp.status_code != 200:
            logger.error("OAuth token exchange failed (HTTP %d)", resp.status_code)
            return HTMLResponse(
                _ERROR_HTML.format(error_message="Salesforce rejected the authorization. Please try again."),
                status_code=502,
            )

        token_data = resp.json()

    instance_url = token_data.get("instance_url", "")
    if not _validate_instance_url(instance_url):
        logger.error("OAuth returned invalid instance_url")
        return HTMLResponse(
            _ERROR_HTML.format(error_message="Invalid Salesforce instance URL returned."),
            status_code=502,
        )

    # Auto-detect Pardot Business Unit ID from Salesforce
    pardot_buid = await detect_pardot_business_unit_id(
        token_data["access_token"], instance_url
    )

    # Generate a cryptographically secure session token
    session_token = secrets.token_urlsafe(48)

    tokens = UserTokens(
        access_token=token_data["access_token"],
        refresh_token=token_data.get("refresh_token", ""),
        instance_url=instance_url,
        issued_at=time.time(),
        pardot_business_unit_id=pardot_buid,
    )
    store.put(session_token, tokens)

    logger.info(
        "Session created: %s (instance: %s)",
        _token_fingerprint(session_token),
        instance_url,
    )

    # Build server URL for config example
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost:8000"))
    server_url = f"{scheme}://{host}"

    return HTMLResponse(
        _SUCCESS_HTML.format(
            session_token=html.escape(session_token),
            instance_url=html.escape(instance_url),
            server_url=html.escape(server_url),
        )
    )


# ---------------------------------------------------------------------------
# /oauth/status — check connection (requires Bearer session_token)
# ---------------------------------------------------------------------------


async def oauth_status(request: Request) -> JSONResponse:
    """Check whether the session token has a connected Salesforce account."""
    session_token = _extract_session_token(request)
    if not session_token:
        return JSONResponse({"error": "Bearer token required"}, status_code=401)

    store = get_token_store()
    if not store:
        return JSONResponse({"connected": False, "mode": "not_configured"})

    tokens = store.get(session_token)
    if tokens:
        return JSONResponse({
            "connected": True,
            "instance_url": tokens["instance_url"],
        })
    return JSONResponse({"connected": False})


# ---------------------------------------------------------------------------
# /oauth/revoke — remove session (requires Bearer session_token)
# ---------------------------------------------------------------------------


async def oauth_revoke(request: Request) -> JSONResponse:
    """Remove stored OAuth tokens for the given session token."""
    session_token = _extract_session_token(request)
    if not session_token:
        return JSONResponse({"error": "Bearer token required"}, status_code=401)

    store = get_token_store()
    if not store:
        return JSONResponse({"error": "Token storage not configured"}, status_code=503)

    removed = store.delete(session_token)
    logger.info("Session revoked: %s (found=%s)", _token_fingerprint(session_token), removed)
    return JSONResponse({"success": True, "was_connected": removed})
