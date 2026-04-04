"""
Tests for MCP Gateway

Basic unit tests for the core components.
"""

import pytest
from unittest.mock import Mock, patch


# -----------------------------------------------------------------------------
# OAuth Tests
# -----------------------------------------------------------------------------

class TestPKCE:
    """Test PKCE code generation and verification."""

    def test_generate_code_verifier_length(self):
        """Code verifier should be correct length."""
        from auth.oauth import generate_code_verifier
        
        verifier = generate_code_verifier(128)
        assert len(verifier) == 128

    def test_generate_code_verifier_charset(self):
        """Code verifier should only contain unreserved characters."""
        from auth.oauth import generate_code_verifier
        import string
        
        charset = set(string.ascii_letters + string.digits + "-._~")
        verifier = generate_code_verifier(128)
        
        assert all(c in charset for c in verifier)

    def test_generate_code_challenge_s256(self):
        """S256 challenge should be SHA256 hash."""
        from auth.oauth import generate_code_challenge
        import base64
        import hashlib
        
        verifier = "dBjftJeZ4CVP-mB92K0uhhARandOM_verifier_128_chars"
        challenge = generate_code_challenge(verifier, "S256")
        
        # Verify manually
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
        
        assert challenge == expected

    def test_generate_code_challenge_plain(self):
        """Plain challenge should equal verifier."""
        from auth.oauth import generate_code_challenge
        
        verifier = "test_verifier"
        challenge = generate_code_challenge(verifier, "plain")
        
        assert challenge == verifier

    def test_verify_code_verifier_success(self):
        """Verification should succeed with matching challenge."""
        from auth.oauth import generate_code_verifier, generate_code_challenge, verify_code_verifier
        
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)
        
        assert verify_code_verifier(verifier, challenge) is True

    def test_verify_code_verifier_failure(self):
        """Verification should fail with wrong verifier."""
        from auth.oauth import generate_code_verifier, generate_code_challenge, verify_code_verifier
        
        verifier1 = generate_code_verifier()
        verifier2 = generate_code_verifier()
        challenge = generate_code_challenge(verifier1)
        
        assert verify_code_verifier(verifier2, challenge) is False


class TestJWTManager:
    """Test JWT token management."""

    def test_create_and_decode_access_token(self):
        """Should create and decode valid access token."""
        from auth.oauth import JWTManager
        
        jwt = JWTManager(secret_key="test-secret-key")
        
        token = jwt.create_access_token(
            user_id="user123",
            client_id="client456",
            scope="mcp:tools",
        )
        
        payload = jwt.decode_token(token)
        
        assert payload is not None
        assert payload.sub == "user123"
        assert payload.client_id == "client456"
        assert payload.scope == "mcp:tools"

    def test_decode_invalid_token(self):
        """Should return None for invalid token."""
        from auth.oauth import JWTManager
        
        jwt = JWTManager(secret_key="test-secret-key")
        
        payload = jwt.decode_token("invalid.token.here")
        
        assert payload is None

    def test_decode_wrong_secret(self):
        """Should fail to decode with wrong secret."""
        from auth.oauth import JWTManager
        
        jwt1 = JWTManager(secret_key="secret1")
        jwt2 = JWTManager(secret_key="secret2")
        
        token = jwt1.create_access_token("user", "client", "scope")
        payload = jwt2.decode_token(token)
        
        assert payload is None

    def test_revoke_token(self):
        """Revoked tokens should fail validation."""
        from auth.oauth import JWTManager
        
        jwt = JWTManager(secret_key="test-secret-key")
        
        token = jwt.create_access_token("user", "client", "scope")
        payload = jwt.decode_token(token)
        
        assert payload is not None
        
        jwt.revoke_token(payload.jti)
        payload = jwt.decode_token(token)
        
        assert payload is None


# -----------------------------------------------------------------------------
# Security Tests
# -----------------------------------------------------------------------------

class TestRateLimiter:
    """Test rate limiting."""

    def test_allowed_request(self):
        """Should allow requests under limit."""
        from security.middleware import RateLimiter
        
        limiter = RateLimiter(requests_per_minute=10, requests_per_hour=100)
        
        for _ in range(5):
            allowed, info = limiter.is_allowed("client1")
            assert allowed is True

    def test_blocked_after_limit(self):
        """Should block after limit exceeded."""
        from security.middleware import RateLimiter
        
        limiter = RateLimiter(requests_per_minute=5, requests_per_hour=100)
        
        for _ in range(5):
            limiter.is_allowed("client1")
        
        allowed, info = limiter.is_allowed("client1")
        assert allowed is False
        assert info.get("blocked") is True

    def test_different_clients_independent(self):
        """Different clients should have separate limits."""
        from security.middleware import RateLimiter
        
        limiter = RateLimiter(requests_per_minute=2, requests_per_hour=100)
        
        # Exhaust client1's limit
        limiter.is_allowed("client1")
        limiter.is_allowed("client1")
        
        # client2 should still be allowed
        allowed, _ = limiter.is_allowed("client2")
        assert allowed is True
        
        # client1 should be blocked
        allowed, _ = limiter.is_allowed("client1")
        assert allowed is False


class TestInputValidator:
    """Test input validation and sanitization."""

    def test_validate_normal_string(self):
        """Normal strings should pass validation."""
        from security.middleware import InputValidator
        
        validator = InputValidator()
        
        valid, result = validator.validate_string("Hello, world!", "message")
        assert valid is True
        assert result == "Hello, world!"

    def test_validate_long_string(self):
        """Overly long strings should be rejected."""
        from security.middleware import InputValidator
        
        validator = InputValidator(max_string_length=100)
        
        valid, result = validator.validate_string("x" * 200, "message")
        assert valid is False
        assert "exceeds maximum length" in result

    def test_dangerous_sql_pattern(self):
        """SQL injection patterns should be rejected."""
        from security.middleware import InputValidator
        
        validator = InputValidator()
        
        valid, result = validator.validate_string(
            "SELECT * FROM users", "query"
        )
        assert valid is False

    def test_sanitize_dict(self):
        """Dict sanitization should work recursively."""
        from security.middleware import InputValidator
        
        validator = InputValidator()
        
        data = {
            "name": "test",
            "password": "secret123",
            "nested": {
                "token": "abc123",
                "value": "safe"
            }
        }
        
        sanitized = validator.sanitize(data)
        
        assert sanitized["name"] == "test"
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["nested"]["token"] == "[REDACTED]"
        assert sanitized["nested"]["value"] == "safe"

    def test_sanitize_html(self):
        """HTML should be escaped."""
        from security.middleware import InputValidator
        
        validator = InputValidator(sanitize_html=True)
        
        sanitized = validator.sanitize("<script>alert('xss')</script>")
        
        assert "<script>" not in sanitized
        assert "&lt;script&gt;" in sanitized


# -----------------------------------------------------------------------------
# Backend Tests
# -----------------------------------------------------------------------------

class TestBackendManager:
    """Test backend management."""

    def test_register_backend(self):
        """Backend registration should work."""
        from backends.manager import BackendManager, BackendDefinition, BackendType
        
        manager = BackendManager()
        
        definition = BackendDefinition(
            id="test_backend",
            name="Test Backend",
            description="A test backend",
            backend_type=BackendType.API_REST,
            tools=["test_tool"],
        )
        
        manager.register_backend(definition)
        
        backends = manager.list_backends()
        assert len(backends) == 1
        assert backends[0]["id"] == "test_backend"

    def test_unregister_backend(self):
        """Backend unregistration should work."""
        from backends.manager import BackendManager, BackendDefinition, BackendType
        
        manager = BackendManager()
        
        definition = BackendDefinition(
            id="test_backend",
            name="Test",
            description="Test",
            backend_type=BackendType.API_REST,
            tools=["tool1", "tool2"],
        )
        
        manager.register_backend(definition)
        assert len(manager.list_backends()) == 1
        
        manager.unregister_backend("test_backend")
        assert len(manager.list_backends()) == 0

    def test_tool_indexing(self):
        """Tool indexing should map tools to backends."""
        from backends.manager import BackendManager, BackendDefinition, BackendType
        
        manager = BackendManager()
        
        definition = BackendDefinition(
            id="backend1",
            name="Backend 1",
            description="Test",
            backend_type=BackendType.API_REST,
            tools=["tool_a", "tool_b"],
        )
        
        manager.register_backend(definition)
        
        assert manager.get_backend_for_tool("tool_a") == "backend1"
        assert manager.get_backend_for_tool("tool_b") == "backend1"
        assert manager.get_backend_for_tool("unknown") is None


# -----------------------------------------------------------------------------
# Integration Tests
# -----------------------------------------------------------------------------

class TestOAuthFlow:
    """Test complete OAuth flow (mocked)."""

    @pytest.mark.asyncio
    async def test_complete_flow(self):
        """Test registration, authorization, token exchange."""
        from auth.oauth import create_oauth_provider
        
        oauth = create_oauth_provider("test-secret-key")
        
        # 1. Register client
        client = oauth.register_client(
            client_name="Test App",
            redirect_uris=["http://localhost:3000/callback"],
        )
        
        assert client.client_id.startswith("client_")
        
        # 2. Generate PKCE
        from auth.oauth import generate_code_verifier, generate_code_challenge
        
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)
        
        # 3. Create authorization code
        code = oauth.create_authorization_code(
            client_id=client.client_id,
            redirect_uri="http://localhost:3000/callback",
            code_challenge=challenge,
            code_challenge_method="S256",
            scope="mcp:tools",
        )
        
        assert code is not None
        
        # 4. Exchange code for tokens
        tokens = oauth.exchange_code_for_token(
            code=code,
            code_verifier=verifier,
            client_id=client.client_id,
            redirect_uri="http://localhost:3000/callback",
        )
        
        assert tokens is not None
        assert tokens.access_token is not None
        assert tokens.refresh_token is not None
        
        # 5. Validate access token
        user_info = oauth.validate_access_token(tokens.access_token)
        
        assert user_info is not None
        assert user_info["scope"] == "mcp:tools"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
