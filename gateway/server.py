"""
MCP Gateway Server

The main MCP server that accepts connections from MCP clients (Cursor, Claude Code)
and routes requests to backend services through OAuth authentication.

Architecture:
    [MCP Client] --(OAuth + MCP)--> [Gateway Server] --(MCP/API)--> [Backend Services]

Features:
- OAuth 2.1 with PKCE for client authentication
- Rate limiting and security middleware
- Dynamic backend discovery and tool aggregation
- Audit logging
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel

# Setup path for local imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import (
    GatewayConfig, 
    get_config, 
    BACKEND_DEFINITIONS,
    OAuthSettings,
    SecuritySettings,
    BackendSettings,
    ServerSettings,
)
from auth.oauth import (
    OAuthProvider, 
    create_oauth_provider,
    generate_code_verifier,
    generate_code_challenge,
)
from security.middleware import (
    SecurityContext, 
    RateLimiter, 
    InputValidator, 
    AuditLogger,
    IPRestrictions,
)
from backends.manager import (
    BackendManager, 
    BackendDefinition, 
    BackendType,
    BackendStatus,
)
from connectors import (
    ConnectorRegistry,
    initialize_connectors,
    get_registry,
)

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Application State
# -----------------------------------------------------------------------------

@dataclass
class AppState:
    """Global application state."""
    config: GatewayConfig
    oauth: OAuthProvider
    security: SecurityContext
    backends: BackendManager
    connectors: ConnectorRegistry
    started_at: datetime = None

    def __post_init__(self):
        self.started_at = datetime.utcnow()


state: Optional[AppState] = None


# -----------------------------------------------------------------------------
# FastAPI Lifespan
# -----------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    global state
    
    # Startup
    config = get_config()
    
    # Initialize OAuth
    oauth = create_oauth_provider(
        secret_key=config.oauth.jwt_secret_key,
        access_token_expire_minutes=config.oauth.access_token_expire_minutes,
        refresh_token_expire_days=config.oauth.refresh_token_expire_days,
    )
    
    # Initialize security
    audit_logger = AuditLogger(
        log_path=config.security.audit_log_path,
        enabled=config.security.audit_enabled,
        sensitive_fields=config.security.audit_sensitive_fields,
    )
    security = SecurityContext(
        rate_limiter=RateLimiter(
            requests_per_minute=config.security.rate_limit_requests_per_minute,
            requests_per_hour=config.security.rate_limit_requests_per_hour,
        ),
        validator=InputValidator(
            max_string_length=config.security.max_string_length,
            max_request_size=config.security.max_request_size_bytes,
            sanitize_html=config.security.sanitize_html,
        ),
        audit_logger=audit_logger,
        ip_restrictions=IPRestrictions(
            whitelist=config.security.ip_whitelist,
            blacklist=config.security.ip_blacklist,
        ),
    )
    
    # Initialize backend manager
    backends = BackendManager(
        health_check_interval=config.backend.health_check_interval_seconds,
        unhealthy_threshold=config.backend.unhealthy_threshold,
    )
    
    # Register backends from definitions
    for backend_id, backend_def in BACKEND_DEFINITIONS.items():
        definition = BackendDefinition(
            id=backend_id,
            name=backend_def["name"],
            description=backend_def["description"],
            backend_type=BackendType.MCP_STDIO if backend_def["type"] == "mcp" else BackendType.API_REST,
            enabled=True,
            requires_auth=backend_def.get("requires_auth", False),
            env_key=backend_def.get("env_key"),
            tools=backend_def.get("tools", []),
            command=backend_def.get("command"),
            args=backend_def.get("args", []),
            env={backend_def["env_key"]: os.getenv(backend_def["env_key"], "")} 
                if backend_def.get("env_key") else {},
            url=backend_def.get("url"),
            base_url=backend_def.get("base_url"),
            auth_type=backend_def.get("auth_type"),
        )
        backends.register_backend(definition)
    
    await backends.start()
    
    # Initialize connectors from environment
    connectors = await initialize_connectors()
    
    # Store state
    state = AppState(
        config=config,
        oauth=oauth,
        security=security,
        backends=backends,
        connectors=connectors,
    )
    
    logger.info(f"MCP Gateway started on {config.server.host}:{config.server.port}")
    
    yield
    
    # Shutdown
    await backends.stop()
    await connectors.close_all()
    logger.info("MCP Gateway stopped")


# -----------------------------------------------------------------------------
# FastAPI App
# -----------------------------------------------------------------------------

app = FastAPI(
    title="MCP Gateway",
    description="OAuth-authenticated MCP proxy for third-party services",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Authentication Dependencies
# -----------------------------------------------------------------------------

async def get_current_user(
    request: Request,
    authorization: Optional[str] = None,
) -> Dict[str, Any]:
    """
    FastAPI dependency to extract and validate authenticated user.
    
    Raises 401 if not authenticated.
    """
    if not authorization:
        authorization = request.headers.get("Authorization")
    
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")
    
    token = authorization[7:]  # Remove "Bearer " prefix
    
    user_info = state.oauth.validate_access_token(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return user_info


async def get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# -----------------------------------------------------------------------------
# OAuth Endpoints
# -----------------------------------------------------------------------------

class ClientRegistrationRequest(BaseModel):
    """OAuth client registration request."""
    client_name: str
    redirect_uris: List[str]
    is_confidential: bool = True


class AuthorizeRequest(BaseModel):
    """OAuth authorization request."""
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str = "S256"
    scope: str = "mcp:tools"
    state: Optional[str] = None


class TokenRequest(BaseModel):
    """OAuth token request."""
    grant_type: str
    code: Optional[str] = None
    code_verifier: Optional[str] = None
    client_id: str
    redirect_uri: str
    refresh_token: Optional[str] = None


@app.post("/oauth/register", tags=["OAuth"])
async def register_client(req: ClientRegistrationRequest):
    """Register a new OAuth client."""
    client = state.oauth.register_client(
        client_name=req.client_name,
        redirect_uris=req.redirect_uris,
        is_confidential=req.is_confidential,
    )
    return {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
    }


@app.get("/oauth/authorize", tags=["OAuth"])
async def authorize_page(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
    scope: str = "mcp:tools",
    state: Optional[str] = None,
):
    """
    OAuth authorization endpoint - shows consent page.
    
    For POC, auto-approves. In production, show UI for user consent.
    """
    # Validate client and redirect URI
    client = state.oauth.get_client(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    if not state.oauth.validate_redirect_uri(client_id, redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
    # For POC: auto-approve and redirect
    # In production: render consent page, get user approval
    code = state.oauth.create_authorization_code(
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope,
    )
    
    # Build redirect URL
    redirect_url = f"{redirect_uri}?code={code}"
    if state:
        redirect_url += f"&state={state}"
    
    # Log the authorization
    if state.security.audit:
        state.security.audit.log(
            event_type="oauth_authorize",
            client_id=client_id,
            user_id="demo_user",
            ip_address="unknown",
            resource="oauth",
            action="authorize",
            success=True,
            details={"scope": scope},
        )
    
    # For POC: return JSON with redirect info
    # In production: return HTMLResponse with consent page or redirect
    return {
        "code": code,
        "redirect_uri": redirect_uri,
        "state": state,
        "message": "Authorization granted (auto-approved for POC)",
    }


@app.post("/oauth/token", tags=["OAuth"])
async def token_endpoint(req: TokenRequest):
    """OAuth token endpoint - exchange code for tokens."""
    if req.grant_type == "authorization_code":
        if not req.code or not req.code_verifier:
            raise HTTPException(status_code=400, detail="Missing code or code_verifier")
        
        token_pair = state.oauth.exchange_code_for_token(
            code=req.code,
            code_verifier=req.code_verifier,
            client_id=req.client_id,
            redirect_uri=req.redirect_uri,
        )
        
        if not token_pair:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        return {
            "access_token": token_pair.access_token,
            "refresh_token": token_pair.refresh_token,
            "token_type": token_pair.token_type,
            "expires_in": token_pair.expires_in,
            "scope": token_pair.scope,
        }
    
    elif req.grant_type == "refresh_token":
        if not req.refresh_token:
            raise HTTPException(status_code=400, detail="Missing refresh_token")
        
        token_pair = state.oauth.refresh_access_token(
            refresh_token=req.refresh_token,
            client_id=req.client_id,
        )
        
        if not token_pair:
            raise HTTPException(status_code=400, detail="Invalid refresh token")
        
        return {
            "access_token": token_pair.access_token,
            "refresh_token": token_pair.refresh_token,
            "token_type": token_pair.token_type,
            "expires_in": token_pair.expires_in,
            "scope": token_pair.scope,
        }
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")


@app.post("/oauth/revoke", tags=["OAuth"])
async def revoke_token(request: Request):
    """Revoke an access or refresh token."""
    body = await request.json()
    token = body.get("token")
    
    if not token:
        raise HTTPException(status_code=400, detail="Missing token")
    
    success = state.oauth.revoke_token(token)
    return {"revoked": success}


# -----------------------------------------------------------------------------
# MCP Gateway Endpoints
# -----------------------------------------------------------------------------

@app.get("/", tags=["Info"])
async def root():
    """Gateway info endpoint."""
    return {
        "name": state.config.server.server_name,
        "version": state.config.server.server_version,
        "status": "running",
        "started_at": state.started_at.isoformat(),
        "endpoints": {
            "oauth": {
                "register": "/oauth/register",
                "authorize": "/oauth/authorize",
                "token": "/oauth/token",
                "revoke": "/oauth/revoke",
            },
            "api_keys": {
                "create": "/v1/api-keys",
                "usage": "Authorization: Bearer <api_key> or ApiKey: <api_key>",
            },
            "v1_rest_api": {
                "tools": "/v1/tools (public discovery)",
                "tool_schema": "/v1/tools/{tool_name} (public)",
                "call": "/v1/call (requires auth)",
                "batch": "/v1/batch (requires auth)",
                "connectors": "/v1/connectors (public discovery)",
            },
            "mcp_compatible": {
                "tools": "/mcp/tools (requires auth)",
                "call": "/mcp/call (requires auth)",
                "backends": "/mcp/backends (requires auth)",
                "connectors": "/mcp/connectors (requires auth)",
            },
            "health": "/health",
        },
        "documentation": {
            "openapi": "/docs",
            "redoc": "/redoc",
        },
    }


@app.get("/health", tags=["Info"])
async def health():
    """Health check endpoint."""
    backends_healthy = sum(
        1 for b in state.backends.list_backends() 
        if b["status"] == "healthy"
    )
    backends_total = len(state.backends._backends)
    
    return {
        "status": "healthy",
        "uptime_seconds": (datetime.utcnow() - state.started_at).total_seconds(),
        "backends": {
            "healthy": backends_healthy,
            "total": backends_total,
        },
    }


@app.get("/mcp/backends", tags=["MCP Compatible"])
async def list_backends(user: Dict = Depends(get_current_user)):
    """List all available backends and their status."""
    return state.backends.list_backends()


@app.post("/mcp/backends/{backend_id}/connect", tags=["MCP Compatible"])
async def connect_backend(
    backend_id: str, 
    user: Dict = Depends(get_current_user),
    ip: str = Depends(get_client_ip),
):
    """Connect to a specific backend."""
    # Security check
    allowed, info = state.security.check_request(
        client_id=user["client_id"],
        ip_address=ip,
        user_id=user["user_id"],
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=info)
    
    success, error = await state.backends.connect_backend(backend_id)
    
    if not success:
        raise HTTPException(status_code=400, detail=error)
    
    return {"connected": True, "backend_id": backend_id}


@app.get("/mcp/tools", tags=["MCP Compatible"])
async def list_tools(user: Dict = Depends(get_current_user)):
    """List all available tools across backends and connectors (authenticated)."""
    backend_tools = state.backends.list_tools()
    connector_tools = state.connectors.get_all_tools()
    
    return {
        "backend_tools": backend_tools,
        "connector_tools": connector_tools,
        "total": len(backend_tools) + len(connector_tools),
    }


# -----------------------------------------------------------------------------
# Public Discovery Endpoints (No Auth Required)
# -----------------------------------------------------------------------------

@app.get("/v1/tools", tags=["Discovery"])
async def discover_tools():
    """
    Public tool discovery endpoint - no authentication required.
    
    Returns tools in OpenAI-compatible format for easy SDK integration.
    Used by CLIs and SDKs to discover available tools before authentication.
    """
    backend_tools = state.backends.list_tools()
    connector_tools = state.connectors.get_all_tools()
    
    # Format in OpenAI-compatible tool format
    all_tools = []
    
    for tool in backend_tools + connector_tools:
        all_tools.append({
            "type": "function",
            "function": {
                "name": tool.get("name", ""),
                "description": tool.get("description", ""),
                "parameters": tool.get("parameters", {}),
            },
            "x-connector": tool.get("connector"),
            "x-requires-auth": tool.get("requires_auth", False),
        })
    
    return {
        "object": "list",
        "data": all_tools,
        "total": len(all_tools),
    }


@app.get("/v1/tools/{tool_name}", tags=["Discovery"])
async def get_tool_schema(tool_name: str):
    """
    Get JSON schema for a specific tool - no authentication required.
    
    Returns MCP-compatible tool schema for SDK code generation.
    """
    # Check connectors first
    connector_schema = state.connectors.get_tool_schema(tool_name)
    if connector_schema:
        return {
            "name": tool_name,
            "schema": connector_schema,
        }
    
    # Check backends
    for tool in state.backends.list_tools():
        if tool.get("name") == tool_name:
            return {
                "name": tool_name,
                "schema": {
                    "name": tool_name,
                    "description": tool.get("description", ""),
                    "inputSchema": {
                        "type": "object",
                        **tool.get("parameters", {}),
                    },
                },
            }
    
    raise HTTPException(status_code=404, detail=f"Tool not found: {tool_name}")


@app.get("/v1/connectors", tags=["Discovery"])
async def discover_connectors():
    """
    Public connector discovery endpoint - no authentication required.
    
    Lists all available third-party connectors and their status.
    """
    return {
        "connectors": [
            {
                "name": c.get("name"),
                "display_name": c.get("display_name"),
                "description": c.get("description"),
                "tools_count": len(c.get("tools", [])),
                "healthy": c.get("healthy"),
            }
            for c in state.connectors.list_connectors()
        ]
    }


# -----------------------------------------------------------------------------
# API Key Authentication (Alternative to OAuth)
# -----------------------------------------------------------------------------

async def get_current_user_api_key(
    request: Request,
    authorization: Optional[str] = None,
) -> Dict[str, Any]:
    """
    FastAPI dependency for API key authentication (simpler than OAuth).
    
    Supports:
    - Bearer token (OAuth access token)
    - ApiKey header (simple API key)
    
    For API keys, the key IS the access token (created via OAuth register).
    """
    if not authorization:
        authorization = request.headers.get("Authorization") or request.headers.get("ApiKey")
    
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization or ApiKey header")
    
    # Handle ApiKey header
    if authorization.startswith("sk-"):
        token = authorization
    # Handle Bearer token
    elif authorization.startswith("Bearer "):
        token = authorization[7:]  # Remove "Bearer " prefix
    else:
        # Treat as raw API key
        token = authorization
    
    # Validate token
    user_info = state.oauth.validate_access_token(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return user_info


@app.post("/v1/api-keys", tags=["API Keys"])
async def create_api_key(
    req: ClientRegistrationRequest,
):
    """
    Create a simple API key for programmatic access.
    
    This is a simplified flow for CLIs and SDKs that don't want OAuth:
    1. Register with a name and callback URL
    2. Get an API key (sk-...) immediately
    3. Use the API key in Authorization: Bearer sk-... or ApiKey: sk-...
    """
    # Register as OAuth client
    client = state.oauth.register_client(
        client_name=req.client_name,
        redirect_uris=req.redirect_uris or ["urn:ietf:wg:oauth:2.0:oob"],
        is_confidential=False,  # Public client for API key flow
    )
    
    # Create an access token directly (bypass OAuth flow)
    # The API key IS the access token
    token_pair = state.oauth._create_token_pair(
        client_id=client.client_id,
        user_id=f"api-key-{client.client_name}",
        scope="mcp:tools",
    )
    
    return {
        "api_key": token_pair.access_token,
        "client_id": client.client_id,
        "client_name": client.client_name,
        "expires_in": token_pair.expires_in,
        "usage": {
            "header": "Authorization: Bearer <api_key>",
            "alt_header": "ApiKey: <api_key>",
        },
    }


# -----------------------------------------------------------------------------
# v1 REST API Endpoints (OpenAI-Compatible)
# -----------------------------------------------------------------------------

class V1ToolCallRequest(BaseModel):
    """OpenAI-compatible tool call request."""
    tool_name: str
    arguments: Dict[str, Any] = {}
    timeout: int = 120


@app.post("/v1/call", tags=["Tool Execution"])
async def v1_call_tool(
    req: V1ToolCallRequest,
    user: Dict = Depends(get_current_user_api_key),
    ip: str = Depends(get_client_ip),
):
    """
    Execute a tool call - OpenAI-compatible endpoint.
    
    Supports both OAuth Bearer tokens and simple API keys.
    
    Example:
        curl -X POST https://gateway/v1/call \\
          -H "Authorization: Bearer sk-xxx" \\
          -H "Content-Type: application/json" \\
          -d '{"tool_name": "github_search_repositories", "arguments": {"query": "mcp"}}'
    """
    # Security check
    allowed, info = state.security.check_request(
        client_id=user["client_id"],
        ip_address=ip,
        user_id=user["user_id"],
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=info)
    
    # Validate and sanitize arguments
    valid, sanitized = state.security.validate_and_sanitize(
        tool_name=req.tool_name,
        arguments=req.arguments,
    )
    if not valid:
        raise HTTPException(status_code=400, detail=sanitized)
    
    # First try connector tools
    connector_name = state.connectors._tool_index.get(req.tool_name)
    if connector_name:
        success, result = await state.connectors.call_tool(
            tool_name=req.tool_name,
            arguments=sanitized,
        )
    else:
        # Fall back to backend tools
        success, result = await state.backends.call_tool(
            tool_name=req.tool_name,
            arguments=sanitized,
            timeout=req.timeout,
        )
    
    # Audit log
    state.security.log_tool_call(
        client_id=user["client_id"],
        user_id=user["user_id"],
        ip_address=ip,
        tool_name=req.tool_name,
        arguments=req.arguments,
        success=success,
        result_summary=str(result)[:200] if result else None,
    )
    
    if not success:
        return JSONResponse(
            status_code=400,
            content={"error": result},
        )
    
    return {
        "object": "tool.call",
        "tool_name": req.tool_name,
        "success": True,
        "result": result,
    }


@app.post("/v1/batch", tags=["Tool Execution"])
async def v1_batch_call(
    requests: List[V1ToolCallRequest],
    user: Dict = Depends(get_current_user_api_key),
    ip: str = Depends(get_client_ip),
):
    """
    Execute multiple tool calls in a single request.
    
    Maximum 10 tools per batch. Returns results in order.
    """
    if len(requests) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 tools per batch")
    
    results = []
    for req in requests:
        try:
            # Reuse single tool call logic
            result = await v1_call_tool(req, user, ip)
            results.append({
                "tool_name": req.tool_name,
                "success": True,
                "result": result.get("result"),
            })
        except HTTPException as e:
            results.append({
                "tool_name": req.tool_name,
                "success": False,
                "error": e.detail,
            })
        except Exception as e:
            results.append({
                "tool_name": req.tool_name,
                "success": False,
                "error": str(e),
            })
    
    return {
        "object": "tool.batch",
        "results": results,
        "total": len(results),
    }


@app.get("/mcp/connectors", tags=["MCP Compatible"])
async def list_connectors(user: Dict = Depends(get_current_user)):
    """List all registered connectors and their status."""
    return state.connectors.list_connectors()


@app.post("/mcp/connectors/{connector_name}/health", tags=["MCP Compatible"])
async def check_connector_health(
    connector_name: str,
    user: Dict = Depends(get_current_user),
):
    """Check health of a specific connector."""
    connector = state.connectors.get_connector(connector_name)
    if not connector:
        raise HTTPException(status_code=404, detail=f"Connector not found: {connector_name}")
    
    healthy, message = await connector.health_check()
    return {
        "connector": connector_name,
        "healthy": healthy,
        "message": message,
    }


class ToolCallRequest(BaseModel):
    """Tool call request."""
    tool_name: str
    arguments: Dict[str, Any] = {}
    backend_id: Optional[str] = None
    timeout: int = 120


@app.post("/mcp/call", tags=["MCP Compatible"])
async def call_tool(
    req: ToolCallRequest,
    user: Dict = Depends(get_current_user),
    ip: str = Depends(get_client_ip),
):
    """Call a tool on a backend or connector."""
    # Security check
    allowed, info = state.security.check_request(
        client_id=user["client_id"],
        ip_address=ip,
        user_id=user["user_id"],
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=info)
    
    # Validate and sanitize arguments
    valid, sanitized = state.security.validate_and_sanitize(
        tool_name=req.tool_name,
        arguments=req.arguments,
    )
    if not valid:
        raise HTTPException(status_code=400, detail=sanitized)
    
    # First try connector tools
    connector_name = state.connectors._tool_index.get(req.tool_name)
    if connector_name:
        success, result = await state.connectors.call_tool(
            tool_name=req.tool_name,
            arguments=sanitized,
        )
    else:
        # Fall back to backend tools
        success, result = await state.backends.call_tool(
            tool_name=req.tool_name,
            arguments=sanitized,
            backend_id=req.backend_id,
            timeout=req.timeout,
        )
    
    # Audit log
    state.security.log_tool_call(
        client_id=user["client_id"],
        user_id=user["user_id"],
        ip_address=ip,
        tool_name=req.tool_name,
        arguments=req.arguments,
        success=success,
        result_summary=str(result)[:200] if result else None,
    )
    
    if not success:
        return JSONResponse(
            status_code=400,
            content={"error": result},
        )
    
    return {"success": True, "result": result}


# -----------------------------------------------------------------------------
# MCP Server (FastMCP Integration)
# -----------------------------------------------------------------------------

def create_mcp_server():
    """
    Create an MCP server using FastMCP.
    
    This is what MCP clients (Cursor, Claude Code) connect to.
    The gateway acts as an MCP server that proxies to backends.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        logger.error("MCP SDK not installed. Run: pip install mcp")
        return None
    
    config = get_config()
    
    mcp = FastMCP(
        config.server.server_name,
        instructions=config.server.server_instructions,
    )
    
    @mcp.tool()
    def gateway_list_backends() -> str:
        """List all available backend services."""
        backends = state.backends.list_backends()
        return json.dumps(backends, indent=2)
    
    @mcp.tool()
    def gateway_list_tools() -> str:
        """List all available tools across backends."""
        tools = state.backends.list_tools()
        return json.dumps(tools, indent=2)
    
    @mcp.tool()
    def gateway_call_tool(
        tool_name: str,
        arguments: str = "{}",
        backend_id: str = None,
    ) -> str:
        """
        Call a tool on a backend.
        
        Args:
            tool_name: Name of the tool to call
            arguments: JSON string of arguments (default: {})
            backend_id: Optional backend ID to route to
        """
        try:
            args = json.loads(arguments) if isinstance(arguments, str) else arguments
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON arguments"})
        
        # Run async call in sync context
        loop = asyncio.new_event_loop()
        try:
            success, result = loop.run_until_complete(
                state.backends.call_tool(
                    tool_name=tool_name,
                    arguments=args,
                    backend_id=backend_id,
                )
            )
        finally:
            loop.close()
        
        if not success:
            return json.dumps({"error": result})
        
        return json.dumps({"result": result}, indent=2)
    
    @mcp.tool()
    async def gateway_connect_backend(backend_id: str) -> str:
        """Connect to a backend service."""
        success, error = await state.backends.connect_backend(backend_id)
        if not success:
            return json.dumps({"error": error})
        return json.dumps({"connected": backend_id})
    
    return mcp


# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------

def run_server():
    """Run the MCP Gateway server."""
    import uvicorn
    
    config = get_config()
    
    # Run FastAPI server
    uvicorn.run(
        "gateway.server:app",
        host=config.server.host,
        port=config.server.port,
        workers=config.server.workers,
        reload=config.is_development,
    )


def run_mcp_server():
    """Run the MCP server (for stdio connection from MCP clients)."""
    mcp = create_mcp_server()
    if mcp:
        mcp.run()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="MCP Gateway Server")
    parser.add_argument(
        "mode",
        choices=["http", "mcp"],
        default="http",
        help="Server mode: http (FastAPI) or mcp (FastMCP stdio)",
    )
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if os.getenv("DEBUG") else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    
    if args.mode == "http":
        run_server()
    else:
        run_mcp_server()
