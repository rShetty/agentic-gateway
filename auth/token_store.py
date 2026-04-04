"""
Per-User Token Store for MCP Gateway

This module addresses the critical architectural gap between a simple
gateway (shared env-var credentials) and what production systems like
Run Layer provide: per-user, per-service credential storage so that each
authenticated user's tool calls are made with *their own* backend tokens,
not a shared service account.

Architecture:
    Gateway User (JWT) ──► TokenStore ──► Backend Credential
                            └── user_id + connector_name ──► api_key / token

Storage:
    - Default: in-memory (development / single instance)
    - Production: swap `InMemoryTokenStore` for `RedisTokenStore` or a
      database-backed implementation via the `AbstractTokenStore` interface.

Usage (in endpoint handlers):
    token = await token_store.get_token(user_id, connector_name="github")
    if token:
        connector = GitHubConnector(ConnectorConfig(api_key=token))
    else:
        raise HTTPException(403, "No GitHub credentials configured for this user")
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Abstract interface
# -----------------------------------------------------------------------------

class AbstractTokenStore(ABC):
    """Interface for per-user token storage."""

    @abstractmethod
    async def set_token(
        self,
        user_id: str,
        connector_name: str,
        token: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Store a token for a user/connector pair."""

    @abstractmethod
    async def get_token(self, user_id: str, connector_name: str) -> Optional[str]:
        """Retrieve a token for a user/connector pair, or None if absent."""

    @abstractmethod
    async def delete_token(self, user_id: str, connector_name: str) -> bool:
        """Remove a token. Returns True if it existed."""

    @abstractmethod
    async def list_connectors_for_user(self, user_id: str) -> list[str]:
        """List connector names that have stored tokens for a user."""


# -----------------------------------------------------------------------------
# In-memory implementation (development / single-instance)
# -----------------------------------------------------------------------------

class InMemoryTokenStore(AbstractTokenStore):
    """
    Thread-safe in-memory token store.

    Suitable for development and single-process deployments.
    Not suitable for multi-worker or multi-instance deployments — use
    RedisTokenStore in production.
    """

    def __init__(self) -> None:
        # {user_id: {connector_name: {"token": str, "metadata": dict, "stored_at": datetime}}}
        self._store: Dict[str, Dict[str, Dict[str, Any]]] = {}

    async def set_token(
        self,
        user_id: str,
        connector_name: str,
        token: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if user_id not in self._store:
            self._store[user_id] = {}
        self._store[user_id][connector_name] = {
            "token": token,
            "metadata": metadata or {},
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"Stored token for user={user_id[:8]}... connector={connector_name}")

    async def get_token(self, user_id: str, connector_name: str) -> Optional[str]:
        entry = self._store.get(user_id, {}).get(connector_name)
        if entry is None:
            return None
        return entry["token"]

    async def delete_token(self, user_id: str, connector_name: str) -> bool:
        user_store = self._store.get(user_id, {})
        if connector_name in user_store:
            del user_store[connector_name]
            logger.info(f"Deleted token for user={user_id[:8]}... connector={connector_name}")
            return True
        return False

    async def list_connectors_for_user(self, user_id: str) -> list[str]:
        return list(self._store.get(user_id, {}).keys())


# -----------------------------------------------------------------------------
# Global instance (swap out for Redis in production)
# -----------------------------------------------------------------------------

_token_store: AbstractTokenStore = InMemoryTokenStore()


def get_token_store() -> AbstractTokenStore:
    """Return the active token store."""
    return _token_store


def set_token_store(store: AbstractTokenStore) -> None:
    """Replace the active token store (e.g. for testing or Redis)."""
    global _token_store
    _token_store = store
