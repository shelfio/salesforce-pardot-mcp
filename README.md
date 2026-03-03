# Salesforce + Pardot MCP Server

A remote [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server providing Salesforce CRM and Pardot (Marketing Cloud Account Engagement) tools over SSE transport. Built with [FastMCP](https://github.com/jlowin/fastmcp), designed for deployment on [Railway](https://railway.app/).

Users connect via **MCP OAuth 2.1** — Claude Desktop handles authentication automatically with zero configuration.

## How It Works

```
1. In Claude Desktop: Settings → Connectors → Add custom connector
2. Enter server URL: https://your-server.up.railway.app/sse
3. Claude Desktop opens a Salesforce login popup
4. User logs in → Done. All tools appear automatically.
```

Claude Desktop handles token management (acquire, store, refresh) automatically via PKCE-secured OAuth. One Connected App on the server handles all users across all Salesforce organizations.

## Available Tools (17 read-only + 5 write)

The server runs in **read-only mode by default**. Write tools (update/create) are only registered when `ENABLE_WRITE_TOOLS=true` is set.

### Salesforce Tools (`sf_*`)

| Tool | Mode | Description |
|---|---|---|
| `sf_query` | read | Run arbitrary SOQL SELECT queries (read-only enforced) |
| `sf_get_leads` | read | Get leads with filters (status, creation recency, lead source) |
| `sf_get_contacts` | read | Get contacts with filters (name, email, account ID) |
| `sf_update_lead` | **write** | Update lead fields (protected fields blocked) |
| `sf_update_contact` | **write** | Update contact fields (protected fields blocked) |
| `sf_create_lead` | **write** | Create a new lead (LastName + Company required) |
| `sf_pipeline_report` | read | Open opportunities aggregated by stage |
| `sf_get_tasks` | read | Get tasks with filters (who/what ID, status, date range, subject) |
| `sf_get_events` | read | Get events with filters (who/what ID, datetime range) |
| `sf_get_activity_history` | read | Combined tasks + events for a record, sorted by date |

### Pardot Tools (`pardot_*`)

| Tool | Mode | Description |
|---|---|---|
| `pardot_get_prospects` | read | Get prospects with filters (email, score, campaign) |
| `pardot_get_prospect_by_email` | read | Look up a single prospect by email address |
| `pardot_update_prospect` | **write** | Update prospect fields (protected fields blocked) |
| `pardot_get_campaigns` | read | List all campaigns |
| `pardot_get_lists` | read | List all lists |
| `pardot_get_forms` | read | List all forms |
| `pardot_add_prospect_to_list` | **write** | Add a prospect to a list |
| `pardot_get_visitor_activities` | read | Get visitor activities with type enrichment (label + category) and friendly name filtering (`form_submit`, `email_open`, `bounce`, etc.) |
| `pardot_get_form_handlers` | read | List all form handlers |
| `pardot_get_emails` | read | List email templates and sends |
| `pardot_get_lifecycle_history` | read | Get lifecycle stage progression for a prospect |
| `pardot_set_business_unit` | read | Set Pardot Business Unit ID for the current session |

### Visitor Activity Types

`pardot_get_visitor_activities` supports filtering by friendly name (`activity_type_name`) or numeric code (`activity_type`):

| Category | Names | Codes |
|---|---|---|
| **Web** | `click`, `view`/`form_view`/`page_view`, `error`/`form_error`, `success`/`form_submit`/`form_success`, `session`, `site_search`, `visit`, `custom_redirect` | 1, 2, 3, 4, 5, 7, 20, 21 |
| **Email** | `email_sent`, `email_open`, `unsubscribe`, `bounce`, `spam`, `email_preference`, `opt_in`, `third_party_click` | 6, 11, 12, 13, 14, 15, 16, 17 |
| **Opportunity** | `opportunity_created`, `opportunity_won`, `opportunity_lost`, `opportunity_reopen`, `opportunity_linked`, `opportunity_unlinked` | 8, 9, 10, 18, 19, 38 |

Each returned activity is enriched with `activityLabel` and `category` fields.

## Security

| Feature | Details |
|---|---|
| **Read-only by default** | Write tools disabled unless `ENABLE_WRITE_TOOLS=true` is set |
| **Authentication** | Bearer token — session tokens from MCP OAuth 2.1 flow |
| **MCP OAuth (PKCE S256)** | Authorization code flow with mandatory PKCE, timing-safe verification |
| **Redirect URI validation** | Only `https://` allowed (+ `http://localhost` for dev); DCR-registered URIs enforced |
| **Session TTL** | Session tokens expire after 24 hours (configurable via `SESSION_TTL_SECONDS`) |
| **SKIP_AUTH restriction** | `SKIP_AUTH` only works in stdio mode (local), ignored for remote SSE |
| **Rate limiting** | 60 requests/minute per token (sliding window) |
| **DCR rate limiting** | 10 requests/minute per IP for client registration |
| **Memory limits** | Auth codes (500), registered clients (200), refresh tokens (1000) capped to prevent DoS |
| **Security headers** | HSTS, X-Content-Type-Options, X-Frame-Options, CSP `default-src 'none'`, Cache-Control `no-store` |
| **SOQL injection protection** | User input escaped before inclusion in queries |
| **Read-only enforcement** | `sf_query` only accepts SELECT statements |
| **SF protected fields** | `OwnerId`, `IsConverted`, `IsDeleted`, `MasterRecordId` cannot be updated (case-insensitive) |
| **Pardot protected fields** | `email`, `score`, `grade`, `isDoNotEmail`, `isDoNotCall`, `salesforceId`, `crmContactFid`, `crmLeadFid` cannot be updated |
| **Pardot ID validation** | Numeric-only validation on prospect/list IDs prevents path injection |
| **Error truncation** | API error messages capped at 200 chars to prevent org data leaks |
| **Audit logging** | SHA-256 key fingerprint logged per request |
| **Token encryption** | Per-user OAuth tokens encrypted at rest with Fernet (AES-128-CBC) |
| **HMAC cache keys** | Client cache uses HMAC-hashed keys to prevent raw token exposure in memory |
| **Instance URL validation** | Only `*.salesforce.com`, `*.force.com`, `*.salesforce.mil`, `*.cloudforce.com` accepted |
| **Input sanitization** | Client names sanitized (control chars stripped, length limited) |
| **Header injection protection** | Pardot Business Unit ID validated as alphanumeric before use in HTTP headers |

## Prerequisites

- **Python 3.10+** (uses `str | None` union syntax)
- **Salesforce Connected App** with OAuth enabled

### Creating a Connected App

1. In Salesforce: **Setup → App Manager → New Connected App**
2. Enable OAuth Settings
3. Set the callback URL to `https://your-server.up.railway.app/oauth/callback`
4. Add OAuth scopes: `api`, `refresh_token`, `pardot_api`
5. Save and note the **Consumer Key** and **Consumer Secret**

## Setup

### Local Development

```bash
git clone https://github.com/DaniilMai/salesforce-pardot-mcp.git
cd salesforce-pardot-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your Connected App credentials

python server.py
# → Listening on http://0.0.0.0:8000 (SSE)
# → Health check: http://localhost:8000/health
```

### Railway Deployment

1. Push the repo to GitHub (or connect Railway to the repo directly)
2. Create a new Railway service from the repo
3. Set environment variables (see table below) as Railway service variables
4. Set health check path to `/health`
5. Deploy

The included `railway.toml` and `Dockerfile` handle the rest.

```bash
# Or build and run manually:
docker build -t sf-mcp .
docker run -p 8000:8000 --env-file .env sf-mcp
```

## Connecting Claude Desktop

1. Open Claude Desktop: **Settings → Connectors → Add custom connector**
2. Enter URL: `https://your-server.up.railway.app/sse`
3. Leave OAuth Client ID/Secret empty (Dynamic Client Registration handles it)
4. Click Add → Salesforce login popup → Done

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SF_OAUTH_CLIENT_ID` | Yes | Connected App consumer key |
| `SF_OAUTH_CLIENT_SECRET` | Yes | Connected App consumer secret |
| `SF_OAUTH_REDIRECT_URI` | Yes | OAuth callback URL (e.g. `https://your-server/oauth/callback`) |
| `SF_OAUTH_LOGIN_URL` | No | Salesforce login URL (default: `https://login.salesforce.com`) |
| `ENCRYPTION_KEY` | Yes | Fernet key for token encryption (see below) |
| `PORT` | No | Server port (default: `8000`) |
| `ENABLE_WRITE_TOOLS` | No | Set to `true` to enable write tools (default: disabled, read-only mode) |
| `SESSION_TTL_SECONDS` | No | Session token lifetime in seconds (default: `86400` — 24 hours) |

Generate an encryption key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

See `.env.example` for a full template with comments.

## Running Tests

```bash
# Unit tests (no Salesforce connection needed)
python -m pytest tests/test_security.py -v

# MCP OAuth tests (PKCE, token exchange, security hardening)
python -m pytest tests/test_mcp_oauth.py -v

# Integration tests (starts server subprocess)
python -m pytest tests/test_integration.py -v

# All tests via Docker
docker build -f Dockerfile.test -t sf-pardot-mcp-tests .
docker run --rm sf-pardot-mcp-tests
```

## Project Structure

```
server.py              # Entry point — FastMCP + SSE + health + OAuth routes + security headers
auth.py                # Bearer token middleware (session tokens from MCP OAuth)
user_context.py        # ContextVar for per-request user identity
token_store.py         # Fernet-encrypted per-user OAuth token storage (HMAC-keyed)
oauth.py               # Shared OAuth utilities (SF config, instance URL validation, BUID detection)
mcp_oauth.py           # MCP OAuth 2.1 Authorization Server (RFC 9728, RFC 8414, RFC 7591)
tools/
  __init__.py          # Re-exports ALL_TOOLS list (17 read + 5 write, write opt-in)
  salesforce.py        # 10 Salesforce tools (SOQL, CRUD, pipeline, activities)
  pardot.py            # 12 Pardot tools (prospects, campaigns, activities, emails, config)
tests/
  test_security.py     # Unit tests — SOQL injection, field protection, auth, rate limiting, activity types
  test_mcp_oauth.py    # MCP OAuth tests — PKCE, token exchange, DCR, redirect validation
  test_integration.py  # Integration tests — server startup, health, SSE
Dockerfile             # Production container
Dockerfile.test        # Test runner container
railway.toml           # Railway deployment config
requirements.txt       # Python dependencies
.env.example           # Environment variable template
```

## License

MIT — see [LICENSE](LICENSE) for details.
