"""
Salesforce + Pardot Remote MCP Server

Entry point that wires together authentication middleware, Salesforce and
Pardot tools, and a health-check endpoint. Runs over SSE transport for
Claude Desktop compatibility.

Usage:
    python server.py          # starts on PORT (default 8000)
    docker build -t sf-mcp .  # containerize for Railway
"""

import os
import logging

from dotenv import load_dotenv
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from auth import BearerAuthMiddleware
from tools import ALL_TOOLS
from mcp_oauth import (
    protected_resource_metadata,
    authorization_server_metadata,
    oauth_authorize,
    mcp_oauth_callback,
    oauth_token,
    oauth_register,
)

# Load .env for local development (no-op if .env is absent)
# Use explicit path so it works regardless of working directory (e.g. stdio via Claude Desktop)
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="Salesforce-Pardot-MCP",
    instructions=(
        "MCP server providing Salesforce CRM and Pardot "
        "(Marketing Cloud Account Engagement) tools.\n\n"
        "Users connect via MCP OAuth 2.1 (Claude Desktop 'Add custom connector').\n\n"
        "Use sf_* tools for Salesforce operations — SOQL queries, "
        "lead/contact CRUD, pipeline reporting, and activity history "
        "(tasks and events).\n\n"
        "Use pardot_* tools for Pardot operations — prospects, "
        "campaigns, lists, forms, visitor activities, emails, "
        "and lifecycle history."
    ),
)

# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------

mcp.add_middleware(BearerAuthMiddleware())

# ---------------------------------------------------------------------------
# Register all tools
# ---------------------------------------------------------------------------

for tool_fn in ALL_TOOLS:
    mcp.add_tool(tool_fn)

logger.info("Registered %d MCP tools", len(ALL_TOOLS))

# ---------------------------------------------------------------------------
# Health endpoint (used by Railway health checks)
# ---------------------------------------------------------------------------


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# MCP OAuth endpoints (RFC 9728 / RFC 8414)
# ---------------------------------------------------------------------------


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def _protected_resource(request: Request):
    return await protected_resource_metadata(request)


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def _auth_server_metadata(request: Request):
    return await authorization_server_metadata(request)


@mcp.custom_route("/oauth/authorize", methods=["GET"])
async def _oauth_authorize(request: Request):
    return await oauth_authorize(request)


@mcp.custom_route("/oauth/token", methods=["POST"])
async def _oauth_token(request: Request):
    return await oauth_token(request)


@mcp.custom_route("/oauth/register", methods=["POST"])
async def _oauth_register(request: Request):
    return await oauth_register(request)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def _oauth_callback(request: Request):
    return await mcp_oauth_callback(request)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    transport = os.environ.get("MCP_TRANSPORT", "sse").lower()

    if transport == "stdio":
        # --- stdio mode: Claude Desktop runs this process directly ---
        logger.info("Starting Salesforce-Pardot MCP server (stdio)")
        mcp.run(transport="stdio")
    else:
        # --- SSE mode: remote deployment (Railway) or local dev ---
        port = int(os.environ.get("PORT", 8000))
        ssl_certfile = os.environ.get("SSL_CERTFILE")
        ssl_keyfile = os.environ.get("SSL_KEYFILE")

        if ssl_certfile and ssl_keyfile:
            logger.info("Starting Salesforce-Pardot MCP server on port %d (SSE + HTTPS)", port)
            mcp.run(
                transport="sse",
                host="0.0.0.0",
                port=port,
                uvicorn_config={"ssl_certfile": ssl_certfile, "ssl_keyfile": ssl_keyfile},
            )
        else:
            logger.warning(
                "Starting Salesforce-Pardot MCP server on port %d (SSE) WITHOUT TLS. "
                "Bearer tokens will be transmitted in cleartext. Set SSL_CERTFILE and "
                "SSL_KEYFILE environment variables to enable HTTPS, or use a TLS-terminating "
                "reverse proxy (e.g. Railway, Nginx).",
                port,
            )
            mcp.run(transport="sse", host="0.0.0.0", port=port)
