"""
SQLite Database Storage for MCP Gateway

This module provides persistent storage for:
- OAuth clients (client_id, client_secret, registration info)
- User credentials (JWT tokens for MCP clients)
- Third-party tokens (GitHub, Slack, Linear, etc.)

Schema:
    - oauth_clients: Registered OAuth applications
    - user_credentials: User JWT tokens (for MCP client auth)
    - connector_tokens: Third-party tokens per user per connector
    - auth_codes: OAuth authorization codes
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("MCP_GATEWAY_DB_PATH", "data/gateway.db")


def get_db_path() -> Path:
    """Get database path, creating data directory if needed."""
    path = Path(DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def init_db() -> sqlite3.Connection:
    """Initialize database with schema."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    
    # OAuth Clients table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
            client_name TEXT NOT NULL,
            client_secret TEXT,
            redirect_uris TEXT NOT NULL,
            is_confidential INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # User Credentials (JWT tokens for MCP clients)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_credentials (
            user_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            access_token TEXT NOT NULL,
            refresh_token TEXT,
            token_type TEXT DEFAULT 'Bearer',
            expires_at TEXT NOT NULL,
            scope TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_id, client_id)
        )
    """)
    
    # Connector Tokens (Third-party tokens per user)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS connector_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            connector_name TEXT NOT NULL,
            token TEXT NOT NULL,
            token_type TEXT DEFAULT 'Bearer',
            refresh_token TEXT,
            expires_at TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, connector_name)
        )
    """)
    
    # Authorization Codes (for OAuth flow)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id TEXT,
            redirect_uri TEXT NOT NULL,
            scope TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    # Revoked Tokens (for token revocation)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti TEXT PRIMARY KEY,
            revoked_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    
    # Create indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_connector_tokens_user ON connector_tokens(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_connector_tokens_connector ON connector_tokens(connector_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_creds_user ON user_credentials(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at)")
    
    conn.commit()
    logger.info(f"Database initialized at {get_db_path()}")
    
    return conn


def get_connection() -> sqlite3.Connection:
    """Get database connection (creates if needed)."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


# -----------------------------------------------------------------------------
# OAuth Client Operations
# -----------------------------------------------------------------------------

def save_oauth_client(
    client_id: str,
    client_name: str,
    client_secret: Optional[str],
    redirect_uris: List[str],
    is_confidential: bool = True,
) -> None:
    """Save or update OAuth client."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT OR REPLACE INTO oauth_clients 
        (client_id, client_name, client_secret, redirect_uris, is_confidential, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (client_id, client_name, client_secret, json.dumps(redirect_uris), 
          1 if is_confidential else 0, now, now))
    conn.commit()


def get_oauth_client(client_id: str) -> Optional[Dict[str, Any]]:
    """Get OAuth client by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)
    ).fetchone()
    if not row:
        return None
    return {
        "client_id": row["client_id"],
        "client_name": row["client_name"],
        "client_secret": row["client_secret"],
        "redirect_uris": json.loads(row["redirect_uris"]),
        "is_confidential": bool(row["is_confidential"]),
    }


def get_oauth_client_by_secret(client_id: str, client_secret: str) -> Optional[Dict[str, Any]]:
    """Get OAuth client by ID and verify secret."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM oauth_clients WHERE client_id = ? AND client_secret = ?", 
        (client_id, client_secret)
    ).fetchone()
    if not row:
        return None
    return {
        "client_id": row["client_id"],
        "client_name": row["client_name"],
        "client_secret": row["client_secret"],
        "redirect_uris": json.loads(row["redirect_uris"]),
        "is_confidential": bool(row["is_confidential"]),
    }


# -----------------------------------------------------------------------------
# User Credential Operations (JWT tokens)
# -----------------------------------------------------------------------------

def save_user_credential(
    user_id: str,
    client_id: str,
    access_token: str,
    refresh_token: Optional[str],
    expires_at: str,
    scope: Optional[str] = None,
) -> None:
    """Save or update user credential (JWT token)."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT OR REPLACE INTO user_credentials 
        (user_id, client_id, access_token, refresh_token, token_type, expires_at, scope, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, client_id, access_token, refresh_token, "Bearer", expires_at, scope, now, now))
    conn.commit()


def get_user_credential(user_id: str, client_id: str) -> Optional[Dict[str, Any]]:
    """Get user credential by user_id and client_id."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM user_credentials WHERE user_id = ? AND client_id = ?",
        (user_id, client_id)
    ).fetchone()
    if not row:
        return None
    return dict(row)


def get_user_credentials_by_user(user_id: str) -> List[Dict[str, Any]]:
    """Get all credentials for a user."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM user_credentials WHERE user_id = ?", (user_id,)
    ).fetchall()
    return [dict(row) for row in rows]


def delete_user_credential(user_id: str, client_id: str) -> bool:
    """Delete user credential."""
    conn = get_connection()
    cursor = conn.execute(
        "DELETE FROM user_credentials WHERE user_id = ? AND client_id = ?",
        (user_id, client_id)
    )
    conn.commit()
    return cursor.rowcount > 0


# -----------------------------------------------------------------------------
# Connector Token Operations (Third-party tokens)
# -----------------------------------------------------------------------------

def save_connector_token(
    user_id: str,
    connector_name: str,
    token: str,
    token_type: str = "Bearer",
    refresh_token: Optional[str] = None,
    expires_at: Optional[str] = None,
    metadata: Optional[Dict] = None,
) -> None:
    """Save or update connector token for a user."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT OR REPLACE INTO connector_tokens 
        (user_id, connector_name, token, token_type, refresh_token, expires_at, metadata, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, connector_name, token, token_type, refresh_token, expires_at, 
          json.dumps(metadata) if metadata else None, now, now))
    conn.commit()


def get_connector_token(user_id: str, connector_name: str) -> Optional[str]:
    """Get connector token for a user."""
    conn = get_connection()
    row = conn.execute(
        "SELECT token FROM connector_tokens WHERE user_id = ? AND connector_name = ?",
        (user_id, connector_name)
    ).fetchone()
    return row["token"] if row else None


def get_connector_token_full(user_id: str, connector_name: str) -> Optional[Dict[str, Any]]:
    """Get full connector token info."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM connector_tokens WHERE user_id = ? AND connector_name = ?",
        (user_id, connector_name)
    ).fetchone()
    return dict(row) if row else None


def list_user_connectors(user_id: str) -> List[str]:
    """List all connectors with tokens for a user."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT connector_name FROM connector_tokens WHERE user_id = ?",
        (user_id,)
    ).fetchall()
    return [row["connector_name"] for row in rows]


def delete_connector_token(user_id: str, connector_name: str) -> bool:
    """Delete connector token."""
    conn = get_connection()
    cursor = conn.execute(
        "DELETE FROM connector_tokens WHERE user_id = ? AND connector_name = ?",
        (user_id, connector_name)
    )
    conn.commit()
    return cursor.rowcount > 0


# -----------------------------------------------------------------------------
# Auth Code Operations
# -----------------------------------------------------------------------------

def save_auth_code(
    code: str,
    client_id: str,
    user_id: str,
    redirect_uri: str,
    scope: Optional[str],
    expires_at: str,
) -> None:
    """Save authorization code."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT INTO auth_codes 
        (code, client_id, user_id, redirect_uri, scope, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (code, client_id, user_id, redirect_uri, scope, expires_at, now))
    conn.commit()


def get_auth_code(code: str) -> Optional[Dict[str, Any]]:
    """Get authorization code."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM auth_codes WHERE code = ?", (code,)
    ).fetchone()
    if not row:
        return None
    
    # Check expiration
    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        conn.execute("DELETE FROM auth_codes WHERE code = ?", (code,))
        conn.commit()
        return None
    
    return dict(row)


def delete_auth_code(code: str) -> bool:
    """Delete authorization code after use."""
    conn = get_connection()
    cursor = conn.execute("DELETE FROM auth_codes WHERE code = ?", (code,))
    conn.commit()
    return cursor.rowcount > 0


# -----------------------------------------------------------------------------
# Token Revocation
# -----------------------------------------------------------------------------

def revoke_token(jti: str, expires_at: str) -> None:
    """Revoke a token."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, ?, ?)",
        (jti, now, expires_at)
    )
    conn.commit()


def is_token_revoked(jti: str) -> bool:
    """Check if token is revoked."""
    conn = get_connection()
    row = conn.execute(
        "SELECT expires_at FROM revoked_tokens WHERE jti = ?", (jti,)
    ).fetchone()
    if not row:
        return False
    
    # Check if expired
    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        conn.execute("DELETE FROM revoked_tokens WHERE jti = ?", (jti,))
        conn.commit()
        return False
    
    return True


# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

def cleanup_expired() -> int:
    """Clean up expired tokens and codes. Returns count of cleaned items."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    
    # Clean expired auth codes
    cursor = conn.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now,))
    
    # Clean expired revoked tokens
    conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now,))
    
    conn.commit()
    return cursor.rowcount