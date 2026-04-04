"""
OAuth 2.1 Authentication for MCP Gateway

Implements OAuth 2.1 with PKCE (Proof Key for Code Exchange) for secure
authentication of MCP clients like Cursor, Claude Code, etc.

Flow:
1. Client registers with redirect_uri and obtains client_id
2. Client redirects user to /oauth/authorize with code_challenge
3. User authenticates and authorizes
4. Gateway redirects back with authorization code
5. Client exchanges code for tokens at /oauth/token with code_verifier
6. Client uses access_token in Authorization header for MCP requests
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from jose import JWTError, jwt
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------

class ClientRegistration(BaseModel):
    """OAuth client registration details."""

    client_id: str
    client_name: str
    redirect_uris: list[str]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_confidential: bool = True
    allowed_scopes: list[str] = Field(default_factory=lambda: ["mcp:tools", "mcp:resources"])


class AuthorizationCode(BaseModel):
    """OAuth 2.1 authorization code with PKCE binding."""

    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str = "S256"
    scope: str
    user_id: str
    expires_at: datetime
    used: bool = False


class TokenPair(BaseModel):
    """Access and refresh token pair."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str


class TokenPayload(BaseModel):
    """JWT token payload."""

    sub: str  # user_id
    client_id: str
    scope: str
    exp: datetime
    iat: datetime
    jti: str  # unique token ID for revocation


@dataclass
class User:
    """Authenticated user."""

    user_id: str
    username: str
    email: Optional[str] = None
    scopes: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


# -----------------------------------------------------------------------------
# PKCE Helpers
# -----------------------------------------------------------------------------

def generate_code_verifier(length: int = 128) -> str:
    """
    Generate a cryptographically random code verifier.

    Per RFC 7636, the code verifier must be:
    - 43-128 characters long
    - Contain only unreserved characters: A-Z, a-z, 0-9, -, ., _, ~
    """
    if length < 43 or length > 128:
        raise ValueError("Code verifier length must be between 43 and 128")
    
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    random_bytes = secrets.token_bytes(length)
    return "".join(charset[b % len(charset)] for b in random_bytes)


def generate_code_challenge(verifier: str, method: str = "S256") -> str:
    """
    Generate code challenge from verifier.

    S256: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    plain: code_challenge = code_verifier
    """
    if method == "plain":
        return verifier
    elif method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    else:
        raise ValueError(f"Unsupported challenge method: {method}")


def verify_code_verifier(verifier: str, challenge: str, method: str = "S256") -> bool:
    """Verify that the code verifier matches the challenge."""
    expected_challenge = generate_code_challenge(verifier, method)
    return secrets.compare_digest(expected_challenge, challenge)


# -----------------------------------------------------------------------------
# JWT Token Management
# -----------------------------------------------------------------------------

class JWTManager:
    """Manages JWT token creation, validation, and revocation."""

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self._revoked_tokens: set[str] = set()  # In production, use Redis

    def create_access_token(
        self,
        user_id: str,
        client_id: str,
        scope: str,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a JWT access token."""
        if expires_delta is None:
            expires_delta = timedelta(minutes=self.access_token_expire_minutes)
        
        now = datetime.utcnow()
        expire = now + expires_delta
        jti = secrets.token_urlsafe(16)
        
        payload = {
            "sub": user_id,
            "client_id": client_id,
            "scope": scope,
            "exp": expire,
            "iat": now,
            "jti": jti,
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(
        self,
        user_id: str,
        client_id: str,
        scope: str,
    ) -> str:
        """Create a JWT refresh token."""
        now = datetime.utcnow()
        expire = now + timedelta(days=self.refresh_token_expire_days)
        jti = secrets.token_urlsafe(16)
        
        payload = {
            "sub": user_id,
            "client_id": client_id,
            "scope": scope,
            "exp": expire,
            "iat": now,
            "jti": jti,
            "refresh": True,
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> Optional[TokenPayload]:
        """Decode and validate a JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
            )
            
            # Check if revoked
            jti = payload.get("jti")
            if jti in self._revoked_tokens:
                logger.warning(f"Attempted use of revoked token: {jti[:8]}...")
                return None
            
            return TokenPayload(
                sub=payload["sub"],
                client_id=payload["client_id"],
                scope=payload["scope"],
                exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
                iat=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
                jti=jti,
            )
        except JWTError as e:
            logger.debug(f"JWT decode failed: {e}")
            return None

    def revoke_token(self, jti: str) -> None:
        """Revoke a token by its ID."""
        self._revoked_tokens.add(jti)
        logger.info(f"Token revoked: {jti[:8]}...")

    def is_revoked(self, jti: str) -> bool:
        """Check if a token is revoked."""
        return jti in self._revoked_tokens


# -----------------------------------------------------------------------------
# OAuth Provider
# -----------------------------------------------------------------------------

class OAuthProvider:
    """
    Complete OAuth 2.1 provider implementation.

    Handles client registration, authorization codes, token issuance,
    and token validation with PKCE support.
    """

    def __init__(
        self,
        jwt_manager: JWTManager,
        code_expire_minutes: int = 10,
    ):
        self.jwt = jwt_manager
        self.code_expire_minutes = code_expire_minutes
        
        # In-memory stores (replace with Redis/DB in production)
        self._clients: Dict[str, ClientRegistration] = {}
        self._auth_codes: Dict[str, AuthorizationCode] = {}
        self._users: Dict[str, User] = {}
        
        # Demo user for POC
        self._demo_user = User(
            user_id="demo_user_001",
            username="demo",
            email="demo@mcp-gateway.local",
            scopes=["mcp:tools", "mcp:resources"],
        )
        self._users[self._demo_user.user_id] = self._demo_user

    # -------------------------------------------------------------------------
    # Client Management
    # -------------------------------------------------------------------------

    def register_client(
        self,
        client_name: str,
        redirect_uris: list[str],
        is_confidential: bool = True,
    ) -> ClientRegistration:
        """Register a new OAuth client."""
        client_id = f"client_{secrets.token_urlsafe(16)}"
        
        client = ClientRegistration(
            client_id=client_id,
            client_name=client_name,
            redirect_uris=redirect_uris,
            is_confidential=is_confidential,
        )
        
        self._clients[client_id] = client
        logger.info(f"Registered OAuth client: {client_name} ({client_id[:12]}...)")
        
        return client

    def get_client(self, client_id: str) -> Optional[ClientRegistration]:
        """Get client by ID."""
        return self._clients.get(client_id)

    def validate_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Validate that redirect_uri is registered for the client."""
        client = self._clients.get(client_id)
        if not client:
            return False
        
        # Exact match or pattern match
        for registered in client.redirect_uris:
            if registered == redirect_uri:
                return True
            # Support wildcard patterns
            if "*" in registered:
                import fnmatch
                if fnmatch.fnmatch(redirect_uri, registered):
                    return True
        
        return False

    # -------------------------------------------------------------------------
    # Authorization Code Flow
    # -------------------------------------------------------------------------

    def create_authorization_code(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        scope: str,
        user_id: Optional[str] = None,
    ) -> str:
        """
        Create an authorization code for the authorization endpoint.

        Called after user authenticates and consents to the scope.
        """
        # Use demo user if no user_id provided (for POC)
        if user_id is None:
            user_id = self._demo_user.user_id
        
        code = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=self.code_expire_minutes)
        
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
            user_id=user_id,
            expires_at=expires_at,
        )
        
        self._auth_codes[code] = auth_code
        logger.debug(f"Created auth code for client {client_id[:12]}..., expires in {self.code_expire_minutes}m")
        
        return code

    def exchange_code_for_token(
        self,
        code: str,
        code_verifier: str,
        client_id: str,
        redirect_uri: str,
    ) -> Optional[TokenPair]:
        """
        Exchange authorization code for tokens at the token endpoint.

        Validates:
        - Code exists and not expired
        - Code not already used (one-time use)
        - PKCE verifier matches challenge
        - Client ID and redirect URI match
        """
        auth_code = self._auth_codes.get(code)
        
        if not auth_code:
            logger.warning(f"Authorization code not found: {code[:12]}...")
            return None
        
        # Check expiration
        if datetime.utcnow() > auth_code.expires_at:
            logger.warning(f"Authorization code expired: {code[:12]}...")
            del self._auth_codes[code]
            return None
        
        # Check if already used
        if auth_code.used:
            logger.warning(f"Authorization code already used: {code[:12]}...")
            # Security: invalidate all tokens for this code
            return None
        
        # Validate client_id
        if auth_code.client_id != client_id:
            logger.warning(f"Client ID mismatch for code {code[:12]}...")
            return None
        
        # Validate redirect_uri
        if auth_code.redirect_uri != redirect_uri:
            logger.warning(f"Redirect URI mismatch for code {code[:12]}...")
            return None
        
        # Verify PKCE
        if not verify_code_verifier(
            code_verifier,
            auth_code.code_challenge,
            auth_code.code_challenge_method,
        ):
            logger.warning(f"PKCE verification failed for code {code[:12]}...")
            return None
        
        # Mark code as used
        auth_code.used = True
        
        # Create tokens
        access_token = self.jwt.create_access_token(
            user_id=auth_code.user_id,
            client_id=client_id,
            scope=auth_code.scope,
        )
        refresh_token = self.jwt.create_refresh_token(
            user_id=auth_code.user_id,
            client_id=client_id,
            scope=auth_code.scope,
        )
        
        logger.info(f"Token issued for user {auth_code.user_id}, client {client_id[:12]}...")
        
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.jwt.access_token_expire_minutes * 60,
            scope=auth_code.scope,
        )

    def refresh_access_token(
        self,
        refresh_token: str,
        client_id: str,
    ) -> Optional[TokenPair]:
        """Refresh an access token using a refresh token."""
        payload = self.jwt.decode_token(refresh_token)
        
        if not payload:
            return None
        
        if payload.client_id != client_id:
            logger.warning(f"Client ID mismatch in refresh token")
            return None
        
        # Create new tokens
        new_access_token = self.jwt.create_access_token(
            user_id=payload.sub,
            client_id=client_id,
            scope=payload.scope,
        )
        new_refresh_token = self.jwt.create_refresh_token(
            user_id=payload.sub,
            client_id=client_id,
            scope=payload.scope,
        )
        
        # Revoke old refresh token
        self.jwt.revoke_token(payload.jti)
        
        return TokenPair(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_in=self.jwt.access_token_expire_minutes * 60,
            scope=payload.scope,
        )

    def revoke_token(self, token: str) -> bool:
        """Revoke an access or refresh token."""
        payload = self.jwt.decode_token(token)
        if payload:
            self.jwt.revoke_token(payload.jti)
            return True
        return False

    # -------------------------------------------------------------------------
    # User Management
    # -------------------------------------------------------------------------

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> Optional[User]:
        """
        Authenticate a user.

        For POC, accepts any username/password.
        In production, verify against your user store.
        """
        # Demo: accept any credentials
        user = User(
            user_id=f"user_{secrets.token_urlsafe(8)}",
            username=username,
            scopes=["mcp:tools", "mcp:resources"],
        )
        self._users[user.user_id] = user
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self._users.get(user_id)

    # -------------------------------------------------------------------------
    # Token Validation (for FastAPI middleware)
    # -------------------------------------------------------------------------

    def validate_access_token(
        self,
        token: str,
        required_scopes: Optional[list[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate an access token and return user info.

        Used by FastAPI Depends() to authenticate requests.
        """
        payload = self.jwt.decode_token(token)
        if not payload:
            return None
        
        # Check scope if required
        if required_scopes:
            token_scopes = set(payload.scope.split())
            if not all(s in token_scopes for s in required_scopes):
                logger.debug(f"Token missing required scopes: {required_scopes}")
                return None
        
        return {
            "user_id": payload.sub,
            "client_id": payload.client_id,
            "scope": payload.scope,
            "jti": payload.jti,
        }


# -----------------------------------------------------------------------------
# FastAPI Integration
# -----------------------------------------------------------------------------

def create_oauth_provider(
    secret_key: str,
    access_token_expire_minutes: int = 30,
    refresh_token_expire_days: int = 7,
) -> OAuthProvider:
    """Factory function to create an OAuth provider."""
    jwt_manager = JWTManager(
        secret_key=secret_key,
        access_token_expire_minutes=access_token_expire_minutes,
        refresh_token_expire_days=refresh_token_expire_days,
    )
    return OAuthProvider(jwt_manager=jwt_manager)
