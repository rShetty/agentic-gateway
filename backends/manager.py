"""
Backend Manager for MCP Gateway

Manages connections to:
1. MCP servers (stdio and HTTP)
2. Direct API integrations

Provides a unified interface for routing tool calls to the appropriate backend.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Backend Types
# -----------------------------------------------------------------------------

class BackendType(Enum):
    """Type of backend integration."""
    MCP_STDIO = "mcp_stdio"
    MCP_HTTP = "mcp_http"
    API_REST = "api_rest"
    API_GRAPHQL = "api_graphql"


class BackendStatus(Enum):
    """Health status of a backend."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DISCONNECTED = "disconnected"


@dataclass
class BackendDefinition:
    """Configuration for a backend service."""
    id: str
    name: str
    description: str
    backend_type: BackendType
    enabled: bool = True
    requires_auth: bool = False
    env_key: Optional[str] = None
    tools: List[str] = field(default_factory=list)
    
    # MCP-specific
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    
    # API-specific
    base_url: Optional[str] = None
    auth_type: Optional[str] = None  # bearer, x-api-key, basic
    
    # Connection settings
    connect_timeout: int = 30
    tool_timeout: int = 120
    max_retries: int = 3


@dataclass
class BackendState:
    """Runtime state of a backend."""
    definition: BackendDefinition
    status: BackendStatus = BackendStatus.DISCONNECTED
    last_healthy: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    total_requests: int = 0
    total_errors: int = 0
    avg_latency_ms: float = 0.0
    
    # MCP session (for MCP backends)
    session: Optional[Any] = None
    
    # HTTP client (for API backends)
    http_client: Optional[Any] = None


# -----------------------------------------------------------------------------
# MCP Backend Handler
# -----------------------------------------------------------------------------

class MCPBackendHandler:
    """
    Handles MCP server connections (stdio and HTTP).
    
    Reuses patterns from Hermes mcp_tool.py but simplified for gateway use.
    """

    def __init__(self):
        self._sessions: Dict[str, Any] = {}
        self._processes: Dict[str, subprocess.Popen] = {}
        self._lock = asyncio.Lock()

    async def connect_stdio(
        self,
        backend_id: str,
        command: str,
        args: List[str],
        env: Dict[str, str],
        timeout: int = 30,
    ) -> Tuple[bool, Optional[str]]:
        """
        Start and connect to an MCP server via stdio.
        
        Returns:
            (success, error_message)
        """
        try:
            # Import MCP SDK
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError:
            return False, "MCP SDK not installed. Run: pip install mcp"
        
        # Build environment
        process_env = os.environ.copy()
        process_env.update(env)
        
        # Filter to safe environment
        safe_keys = {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "SHELL", "TMPDIR"}
        filtered_env = {k: v for k, v in process_env.items() 
                       if k in safe_keys or k.startswith(("MCP_", "GITHUB_", "DATABASE_"))}
        filtered_env.update(env)
        
        server_params = StdioServerParameters(
            command=command,
            args=args,
            env=filtered_env,
        )
        
        try:
            # Connect with timeout
            async with asyncio.timeout(timeout):
                async with stdio_client(server_params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        self._sessions[backend_id] = session
                        logger.info(f"Connected to MCP backend: {backend_id}")
                        return True, None
        except asyncio.TimeoutError:
            return False, f"Connection timeout after {timeout}s"
        except Exception as e:
            return False, f"Connection failed: {e}"

    async def connect_http(
        self,
        backend_id: str,
        url: str,
        headers: Dict[str, str],
        timeout: int = 30,
    ) -> Tuple[bool, Optional[str]]:
        """
        Connect to an MCP server via HTTP.
        
        Returns:
            (success, error_message)
        """
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client
            import httpx
        except ImportError:
            return False, "MCP SDK not installed. Run: pip install mcp"
        
        try:
            client_kwargs = {
                "follow_redirects": True,
                "timeout": httpx.Timeout(float(timeout), read=300.0),
            }
            if headers:
                client_kwargs["headers"] = headers
            
            async with httpx.AsyncClient(**client_kwargs) as http_client:
                async with streamablehttp_client(url, http_client=http_client) as (read, write, _):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        self._sessions[backend_id] = session
                        logger.info(f"Connected to HTTP MCP backend: {backend_id}")
                        return True, None
        except Exception as e:
            return False, f"HTTP connection failed: {e}"

    async def call_tool(
        self,
        backend_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: int = 120,
    ) -> Tuple[bool, Any]:
        """
        Call a tool on an MCP backend.
        
        Returns:
            (success, result_or_error)
        """
        session = self._sessions.get(backend_id)
        if not session:
            return False, f"Backend {backend_id} not connected"
        
        try:
            async with asyncio.timeout(timeout):
                result = await session.call_tool(tool_name, arguments=arguments)
                
                if result.isError:
                    error_text = ""
                    for block in (result.content or []):
                        if hasattr(block, "text"):
                            error_text += block.text
                    return False, error_text or "MCP tool error"
                
                # Extract content
                parts = []
                for block in (result.content or []):
                    if hasattr(block, "text"):
                        parts.append(block.text)
                
                return True, "\n".join(parts) if parts else ""
                
        except asyncio.TimeoutError:
            return False, f"Tool call timeout after {timeout}s"
        except Exception as e:
            return False, f"Tool call failed: {e}"

    async def list_tools(self, backend_id: str) -> Tuple[bool, List[Dict[str, Any]]]:
        """List available tools from an MCP backend."""
        session = self._sessions.get(backend_id)
        if not session:
            return False, []
        
        try:
            result = await session.list_tools()
            tools = []
            for tool in (result.tools if hasattr(result, "tools") else []):
                tools.append({
                    "name": tool.name,
                    "description": getattr(tool, "description", ""),
                    "inputSchema": getattr(tool, "inputSchema", {}),
                })
            return True, tools
        except Exception as e:
            logger.error(f"Failed to list tools for {backend_id}: {e}")
            return False, []

    async def disconnect(self, backend_id: str) -> None:
        """Disconnect from an MCP backend."""
        if backend_id in self._sessions:
            # Session cleanup happens via context manager
            del self._sessions[backend_id]
            logger.info(f"Disconnected from MCP backend: {backend_id}")


# -----------------------------------------------------------------------------
# API Backend Handler
# -----------------------------------------------------------------------------

class APIBackendHandler:
    """
    Handles direct API integrations (REST and GraphQL).
    """

    def __init__(self):
        self._clients: Dict[str, Any] = {}

    async def get_client(self, backend_id: str, base_url: str, headers: Dict[str, str]):
        """Get or create an HTTP client for a backend."""
        if backend_id not in self._clients:
            import httpx
            self._clients[backend_id] = httpx.AsyncClient(
                base_url=base_url,
                headers=headers,
                timeout=httpx.Timeout(30.0, read=300.0),
                follow_redirects=True,
            )
        return self._clients[backend_id]

    async def call_rest(
        self,
        backend_id: str,
        base_url: str,
        headers: Dict[str, str],
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> Tuple[bool, Any]:
        """
        Make a REST API call.
        
        Returns:
            (success, result_or_error)
        """
        client = await self.get_client(backend_id, base_url, headers)
        
        try:
            async with asyncio.timeout(timeout):
                response = await client.request(
                    method=method,
                    url=endpoint,
                    json=json_data,
                    params=params,
                )
                
                if response.status_code >= 400:
                    return False, {
                        "error": f"API error {response.status_code}",
                        "body": response.text[:500],
                    }
                
                # Try JSON, fall back to text
                try:
                    return True, response.json()
                except:
                    return True, {"text": response.text}
                    
        except asyncio.TimeoutError:
            return False, f"API call timeout after {timeout}s"
        except Exception as e:
            return False, f"API call failed: {e}"

    async def call_graphql(
        self,
        backend_id: str,
        base_url: str,
        headers: Dict[str, str],
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> Tuple[bool, Any]:
        """
        Make a GraphQL API call.
        
        Returns:
            (success, result_or_error)
        """
        json_data = {"query": query}
        if variables:
            json_data["variables"] = variables
        
        success, result = await self.call_rest(
            backend_id=backend_id,
            base_url=base_url,
            headers=headers,
            method="POST",
            endpoint="",  # Base URL is the GraphQL endpoint
            json_data=json_data,
            timeout=timeout,
        )
        
        if success and isinstance(result, dict):
            if "errors" in result:
                return False, {"errors": result["errors"]}
            return True, result.get("data", {})
        
        return success, result

    async def disconnect(self, backend_id: str) -> None:
        """Close HTTP client for a backend."""
        if backend_id in self._clients:
            await self._clients[backend_id].aclose()
            del self._clients[backend_id]


# -----------------------------------------------------------------------------
# Backend Manager
# -----------------------------------------------------------------------------

class BackendManager:
    """
    Central manager for all backend connections.
    
    Provides:
    - Backend registration and configuration
    - Connection management
    - Tool discovery and routing
    - Health monitoring
    """

    def __init__(
        self,
        health_check_interval: int = 30,
        unhealthy_threshold: int = 3,
    ):
        self._backends: Dict[str, BackendState] = {}
        self._mcp_handler = MCPBackendHandler()
        self._api_handler = APIBackendHandler()
        self._health_check_interval = health_check_interval
        self._unhealthy_threshold = unhealthy_threshold
        self._tool_index: Dict[str, str] = {}  # tool_name -> backend_id
        self._running = False

    async def start(self) -> None:
        """Start the backend manager and health checks."""
        self._running = True
        asyncio.create_task(self._health_check_loop())
        logger.info("Backend manager started")

    async def stop(self) -> None:
        """Stop all backends and cleanup."""
        self._running = False
        for backend_id in list(self._backends.keys()):
            await self.disconnect_backend(backend_id)
        logger.info("Backend manager stopped")

    # -------------------------------------------------------------------------
    # Backend Registration
    # -------------------------------------------------------------------------

    def register_backend(self, definition: BackendDefinition) -> None:
        """Register a new backend."""
        if definition.id in self._backends:
            logger.warning(f"Backend {definition.id} already registered, replacing")
        
        state = BackendState(definition=definition)
        self._backends[definition.id] = state
        
        # Index tools
        for tool_name in definition.tools:
            self._tool_index[tool_name] = definition.id
        
        logger.info(f"Registered backend: {definition.id} ({definition.backend_type.value})")

    def unregister_backend(self, backend_id: str) -> None:
        """Unregister a backend."""
        if backend_id in self._backends:
            state = self._backends[backend_id]
            # Remove tool index entries
            for tool_name in state.definition.tools:
                self._tool_index.pop(tool_name, None)
            del self._backends[backend_id]
            logger.info(f"Unregistered backend: {backend_id}")

    def get_backend(self, backend_id: str) -> Optional[BackendState]:
        """Get backend state by ID."""
        return self._backends.get(backend_id)

    def list_backends(self) -> List[Dict[str, Any]]:
        """List all registered backends with their status."""
        result = []
        for backend_id, state in self._backends.items():
            result.append({
                "id": backend_id,
                "name": state.definition.name,
                "type": state.definition.backend_type.value,
                "status": state.status.value,
                "enabled": state.definition.enabled,
                "tools": state.definition.tools,
                "requires_auth": state.definition.requires_auth,
                "last_error": state.last_error,
            })
        return result

    # -------------------------------------------------------------------------
    # Connection Management
    # -------------------------------------------------------------------------

    async def connect_backend(self, backend_id: str) -> Tuple[bool, Optional[str]]:
        """
        Connect to a backend.
        
        Returns:
            (success, error_message)
        """
        state = self._backends.get(backend_id)
        if not state:
            return False, f"Backend {backend_id} not registered"
        
        definition = state.definition
        if not definition.enabled:
            return False, f"Backend {backend_id} is disabled"
        
        # Check for required credentials
        if definition.env_key and not os.getenv(definition.env_key):
            return False, f"Missing required credential: {definition.env_key}"
        
        start_time = time.time()
        
        if definition.backend_type == BackendType.MCP_STDIO:
            success, error = await self._mcp_handler.connect_stdio(
                backend_id=backend_id,
                command=definition.command,
                args=definition.args,
                env=definition.env,
                timeout=definition.connect_timeout,
            )
        elif definition.backend_type == BackendType.MCP_HTTP:
            success, error = await self._mcp_handler.connect_http(
                backend_id=backend_id,
                url=definition.url,
                headers=definition.headers,
                timeout=definition.connect_timeout,
            )
        else:
            # API backends don't need explicit connection
            success, error = True, None
        
        latency_ms = (time.time() - start_time) * 1000
        state.avg_latency_ms = latency_ms
        
        if success:
            state.status = BackendStatus.HEALTHY
            state.last_healthy = datetime.utcnow()
            state.consecutive_failures = 0
            logger.info(f"Connected to backend: {backend_id} ({latency_ms:.0f}ms)")
        else:
            state.status = BackendStatus.UNHEALTHY
            state.last_error = error
            state.consecutive_failures += 1
            logger.error(f"Failed to connect to {backend_id}: {error}")
        
        return success, error

    async def disconnect_backend(self, backend_id: str) -> None:
        """Disconnect from a backend."""
        state = self._backends.get(backend_id)
        if not state:
            return
        
        definition = state.definition
        
        if definition.backend_type in (BackendType.MCP_STDIO, BackendType.MCP_HTTP):
            await self._mcp_handler.disconnect(backend_id)
        else:
            await self._api_handler.disconnect(backend_id)
        
        state.status = BackendStatus.DISCONNECTED
        state.session = None
        state.http_client = None

    async def connect_all(self) -> Dict[str, Tuple[bool, Optional[str]]]:
        """Connect to all registered backends."""
        results = {}
        for backend_id, state in self._backends.items():
            if state.definition.enabled:
                results[backend_id] = await self.connect_backend(backend_id)
        return results

    # -------------------------------------------------------------------------
    # Tool Routing
    # -------------------------------------------------------------------------

    def get_backend_for_tool(self, tool_name: str) -> Optional[str]:
        """Find which backend provides a tool."""
        return self._tool_index.get(tool_name)

    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools across backends."""
        tools = []
        for backend_id, tool_name in self._tool_index.items():
            state = self._backends.get(backend_id)
            if state and state.status == BackendStatus.HEALTHY:
                tools.append({
                    "name": tool_name,
                    "backend_id": backend_id,
                    "backend_name": state.definition.name,
                })
        return tools

    async def call_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        backend_id: Optional[str] = None,
        timeout: int = 120,
    ) -> Tuple[bool, Any]:
        """
        Call a tool, routing to the appropriate backend.
        
        Returns:
            (success, result_or_error)
        """
        # Find backend
        if backend_id is None:
            backend_id = self._tool_index.get(tool_name)
        
        if not backend_id:
            return False, f"Tool {tool_name} not found"
        
        state = self._backends.get(backend_id)
        if not state:
            return False, f"Backend {backend_id} not found"
        
        if state.status != BackendStatus.HEALTHY:
            return False, f"Backend {backend_id} is not healthy ({state.status.value})"
        
        definition = state.definition
        start_time = time.time()
        
        try:
            if definition.backend_type == BackendType.MCP_STDIO:
                success, result = await self._mcp_handler.call_tool(
                    backend_id=backend_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    timeout=timeout,
                )
            elif definition.backend_type == BackendType.MCP_HTTP:
                success, result = await self._mcp_handler.call_tool(
                    backend_id=backend_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    timeout=timeout,
                )
            else:
                # API backend - this would need more sophisticated routing
                success, result = await self._call_api_tool(
                    definition, tool_name, arguments, timeout
                )
            
            # Update metrics
            latency_ms = (time.time() - start_time) * 1000
            state.total_requests += 1
            state.avg_latency_ms = (state.avg_latency_ms + latency_ms) / 2
            
            if not success:
                state.total_errors += 1
                state.consecutive_failures += 1
                if state.consecutive_failures >= self._unhealthy_threshold:
                    state.status = BackendStatus.UNHEALTHY
            else:
                state.consecutive_failures = 0
                state.last_healthy = datetime.utcnow()
            
            return success, result
            
        except Exception as e:
            state.total_errors += 1
            state.consecutive_failures += 1
            state.last_error = str(e)
            return False, f"Tool call failed: {e}"

    async def _call_api_tool(
        self,
        definition: BackendDefinition,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout: int,
    ) -> Tuple[bool, Any]:
        """
        Call a tool on an API backend.
        
        This is a simplified implementation - production would need
        tool-specific handlers for each API.
        """
        # Build headers from auth config
        headers = dict(definition.headers)
        if definition.env_key:
            cred = os.getenv(definition.env_key, "")
            if definition.auth_type == "bearer":
                headers["Authorization"] = f"Bearer {cred}"
            elif definition.auth_type == "x-api-key":
                headers["x-api-key"] = cred
            else:
                headers["Authorization"] = f"Bearer {cred}"
        
        # For now, treat tool_name as endpoint and arguments as body
        return await self._api_handler.call_rest(
            backend_id=definition.id,
            base_url=definition.base_url,
            headers=headers,
            method="POST",
            endpoint=f"/{tool_name}",
            json_data=arguments,
            timeout=timeout,
        )

    # -------------------------------------------------------------------------
    # Health Monitoring
    # -------------------------------------------------------------------------

    async def _health_check_loop(self) -> None:
        """Periodically check backend health."""
        while self._running:
            await asyncio.sleep(self._health_check_interval)
            await self._check_all_health()

    async def _check_all_health(self) -> None:
        """Check health of all backends."""
        for backend_id, state in self._backends.items():
            if not state.definition.enabled:
                continue
            
            # MCP backends: try to list tools
            if state.definition.backend_type in (BackendType.MCP_STDIO, BackendType.MCP_HTTP):
                success, tools = await self._mcp_handler.list_tools(backend_id)
                if success:
                    state.status = BackendStatus.HEALTHY
                    state.last_healthy = datetime.utcnow()
                    state.consecutive_failures = 0
                else:
                    state.consecutive_failures += 1
                    if state.consecutive_failures >= self._unhealthy_threshold:
                        state.status = BackendStatus.UNHEALTHY
            
            # API backends: simple ping
            else:
                try:
                    success, _ = await self._api_handler.call_rest(
                        backend_id=backend_id,
                        base_url=state.definition.base_url,
                        headers=state.definition.headers,
                        method="GET",
                        endpoint="",
                        timeout=10,
                    )
                    if success:
                        state.status = BackendStatus.HEALTHY
                        state.consecutive_failures = 0
                except:
                    state.consecutive_failures += 1
