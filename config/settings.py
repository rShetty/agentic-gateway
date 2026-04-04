"""
MCP Gateway Configuration

Centralized settings using Pydantic for validation and environment variable support.
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from typing import Any, Dict, List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class OAuthSettings(BaseSettings):
    """OAuth 2.1 configuration for client authentication."""

    model_config = SettingsConfigDict(env_prefix="OAUTH_")

    # JWT settings
    jwt_secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # PKCE settings
    pkce_code_challenge_method: str = "S256"
    code_verifier_length: int = 128

    # OAuth server endpoints
    authorization_endpoint: str = "/oauth/authorize"
    token_endpoint: str = "/oauth/token"
    revoke_endpoint: str = "/oauth/revoke"

    # Allowed redirect URIs (for validation)
    allowed_redirect_uris: List[str] = Field(default_factory=lambda: [
        "http://localhost:*",
        "https://claude.ai/*",
        "https://cursor.sh/*",
        "vscode://*",
        "cursor://*",
    ])


class SecuritySettings(BaseSettings):
    """Security and rate limiting configuration."""

    model_config = SettingsConfigDict(env_prefix="SECURITY_")

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 60
    rate_limit_requests_per_hour: int = 1000

    # Request validation
    max_request_size_bytes: int = 10 * 1024 * 1024  # 10 MB
    max_tool_call_depth: int = 5
    request_timeout_seconds: int = 300

    # Input sanitization
    sanitize_html: bool = True
    max_string_length: int = 100000

    # Audit logging
    audit_enabled: bool = True
    audit_log_path: str = "logs/audit.log"
    audit_sensitive_fields: List[str] = Field(default_factory=lambda: [
        "password", "token", "secret", "key", "credential", "api_key"
    ])

    # IP restrictions
    ip_whitelist: List[str] = Field(default_factory=list)
    ip_blacklist: List[str] = Field(default_factory=list)


class BackendSettings(BaseSettings):
    """Backend MCP server and API configuration."""

    model_config = SettingsConfigDict(env_prefix="BACKEND_")

    # Connection settings
    connect_timeout_seconds: int = 30
    tool_timeout_seconds: int = 120
    max_concurrent_connections: int = 100

    # Retry settings
    max_retries: int = 3
    retry_backoff_base: float = 1.5

    # Health checks
    health_check_interval_seconds: int = 30
    unhealthy_threshold: int = 3


class ServerSettings(BaseSettings):
    """Main server configuration."""

    model_config = SettingsConfigDict(env_prefix="SERVER_")

    # Server binding
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1

    # TLS/SSL
    ssl_enabled: bool = False
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None

    # CORS
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])
    cors_methods: List[str] = Field(default_factory=lambda: ["GET", "POST", "OPTIONS"])
    cors_headers: List[str] = Field(default_factory=lambda: ["*"])

    # MCP Server info
    server_name: str = "mcp-gateway"
    server_version: str = "0.1.0"
    server_instructions: str = (
        "MCP Gateway - OAuth-authenticated proxy for connecting to "
        "third-party MCP servers and APIs. Use tools to discover available "
        "backends and route requests through this gateway."
    )


class DatabaseSettings(BaseSettings):
    """Database configuration for persistence."""

    model_config = SettingsConfigDict(env_prefix="DATABASE_")

    # SQLite (default, local development)
    sqlite_path: str = "data/gateway.db"

    # Redis (for rate limiting, sessions, caching)
    redis_url: Optional[str] = None
    redis_prefix: str = "mcp_gateway:"


class GatewayConfig(BaseSettings):
    """
    Master configuration for MCP Gateway.

    Loads from environment variables with sensible defaults.
    """

    model_config = SettingsConfigDict(
        env_prefix="MCP_GATEWAY_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    # Environment
    environment: str = Field(default="development")

    # Sub-configurations
    oauth: OAuthSettings = Field(default_factory=OAuthSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    backend: BackendSettings = Field(default_factory=BackendSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)

    # Debug mode
    debug: bool = False

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"environment must be one of {allowed}")
        return v

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"


@lru_cache()
def get_config() -> GatewayConfig:
    """Get cached configuration instance."""
    return GatewayConfig()


# Backend definitions - these are the third-party services we proxy to
BACKEND_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    # Example MCP servers
    "github": {
        "type": "mcp",
        "name": "GitHub",
        "description": "GitHub API via MCP server",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"],
        "env_key": "GITHUB_PERSONAL_ACCESS_TOKEN",
        "tools": ["create_issue", "create_pull_request", "search_repositories", "get_file_contents"],
        "requires_auth": True,
    },
    "filesystem": {
        "type": "mcp",
        "name": "Filesystem",
        "description": "Local filesystem access via MCP server",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "${ALLOWED_DIRS:-/tmp}"],
        "tools": ["read_file", "write_file", "list_directory", "search_files"],
        "requires_auth": False,
    },
    "postgres": {
        "type": "mcp",
        "name": "PostgreSQL",
        "description": "PostgreSQL database via MCP server",
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-postgres"],
        "env_key": "DATABASE_URL",
        "tools": ["query", "list_tables", "describe_table"],
        "requires_auth": True,
    },
    # Example direct API backends
    "openai": {
        "type": "api",
        "name": "OpenAI",
        "description": "OpenAI API direct integration",
        "base_url": "https://api.openai.com/v1",
        "env_key": "OPENAI_API_KEY",
        "auth_type": "bearer",
        "tools": ["chat_completions", "embeddings", "image_generation"],
        "requires_auth": True,
    },
    "anthropic": {
        "type": "api",
        "name": "Anthropic",
        "description": "Anthropic Claude API direct integration",
        "base_url": "https://api.anthropic.com/v1",
        "env_key": "ANTHROPIC_API_KEY",
        "auth_type": "x-api-key",
        "tools": ["messages", "token_count"],
        "requires_auth": True,
    },
    "slack": {
        "type": "api",
        "name": "Slack",
        "description": "Slack API direct integration",
        "base_url": "https://slack.com/api",
        "env_key": "SLACK_BOT_TOKEN",
        "auth_type": "bearer",
        "tools": ["post_message", "list_channels", "get_conversation_history"],
        "requires_auth": True,
    },
    "linear": {
        "type": "api",
        "name": "Linear",
        "description": "Linear API via GraphQL",
        "base_url": "https://api.linear.app/graphql",
        "env_key": "LINEAR_API_KEY",
        "auth_type": "bearer",
        "tools": ["create_issue", "search_issues", "update_issue"],
        "requires_auth": True,
    },
}
