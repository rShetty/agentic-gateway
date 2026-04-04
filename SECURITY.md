# MCP Gateway - Security Architecture

## Overview

This document describes the security architecture of the MCP Gateway, designed to provide secure, authenticated access to third-party services for MCP clients.

## Threat Model

### Assets Protected
1. **User Credentials** - OAuth tokens, API keys
2. **Backend Connections** - MCP server and API connections
3. **Tool Call Data** - Arguments and results of tool invocations
4. **Audit Logs** - Security event history

### Threat Actors
1. **External Attackers** - Network-level attacks, credential theft
2. **Malicious Clients** - Rate limit abuse, injection attacks
3. **Compromised Backends** - Supply chain attacks via MCP servers
4. **Insider Threats** - Privilege escalation, data exfiltration

### Attack Vectors

| Vector | Mitigation |
|--------|------------|
| Credential interception | PKCE, TLS, short-lived tokens |
| Authorization code replay | One-time codes, code binding |
| Token theft | Token rotation, revocation |
| Rate limit bypass | Per-client limits, sliding window |
| SQL injection | Input validation, parameterized queries |
| Command injection | Input validation, allowlists |
| Path traversal | Input validation, sandboxed paths |
| XSS | HTML sanitization, CSP headers |
| SSRF | URL allowlists, no internal access |
| DDoS | Rate limiting, IP restrictions |

## Authentication Flow

```
┌─────────┐          ┌─────────┐          ┌─────────┐          ┌─────────┐
│  Client │          │ Gateway │          │   User  │          │ Backend │
└────┬────┘          └────┬────┘          └────┬────┘          └────┬────┘
     │                    │                    │                    │
     │ 1. Generate PKCE   │                    │                    │
     │    verifier        │                    │                    │
     │    challenge       │                    │                    │
     │                    │                    │                    │
     │ 2. Authorization   │                    │                    │
     │    Request ────────►                    │                    │
     │    + code_challenge │                    │                    │
     │                    │                    │                    │
     │                    │ 3. User consents   │                    │
     │                    │    (auto for POC)  │                    │
     │                    │                    │                    │
     │                    │ 4. Auth Code ──────►                    │
     │◄─────────────────── │                    │                    │
     │                    │                    │                    │
     │ 5. Token Request   │                    │                    │
     │    + code_verifier │                    │                    │
     │    ─────────────────►                    │                    │
     │                    │                    │                    │
     │                    │ 6. Verify PKCE     │                    │
     │                    │    Create JWT      │                    │
     │                    │                    │                    │
     │ 7. Access Token    │                    │                    │
     │◄─────────────────── │                    │                    │
     │                    │                    │                    │
     │ 8. Tool Call       │                    │                    │
     │    + Bearer token  │                    │                    │
     │    ─────────────────►                    │                    │
     │                    │                    │                    │
     │                    │ 9. Validate token  │                    │
     │                    │    Check rate limit│                    │
     │                    │    Sanitize input  │                    │
     │                    │                    │                    │
     │                    │ 10. Call backend   │                    │
     │                    │     ──────────────────────────────────►│
     │                    │                    │                    │
     │                    │ 11. Result         │                    │
     │                    │◄────────────────────────────────────── │
     │                    │                    │                    │
     │ 12. Response       │                    │                    │
     │◄─────────────────── │                    │                    │
     │                    │                    │                    │
```

## Security Controls

### 1. OAuth 2.1 with PKCE

**Purpose**: Prevent authorization code interception attacks

**Implementation**:
- Code verifier: 128 random bytes (base64url encoded)
- Code challenge: SHA256 hash of verifier
- Challenge binding: Code bound to specific challenge
- One-time codes: Codes invalidated after use

**Code**:
```python
def generate_code_verifier(length: int = 128) -> str:
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    random_bytes = secrets.token_bytes(length)
    return "".join(charset[b % len(charset)] for b in random_bytes)

def verify_code_verifier(verifier: str, challenge: str, method: str = "S256") -> bool:
    expected = generate_code_challenge(verifier, method)
    return secrets.compare_digest(expected, challenge)
```

### 2. JWT Token Security

**Purpose**: Stateless authentication with revocation support

**Implementation**:
- Algorithm: HS256 (symmetric)
- Token lifetime: 30 minutes (configurable)
- Refresh tokens: 7 days, single-use
- Token ID (jti): Unique identifier for revocation

**Claims**:
```json
{
  "sub": "user_abc123",
  "client_id": "client_xyz789",
  "scope": "mcp:tools mcp:resources",
  "exp": 1704067200,
  "iat": 1704065400,
  "jti": "unique_token_id"
}
```

### 3. Rate Limiting

**Purpose**: Prevent abuse and resource exhaustion

**Algorithm**: Sliding window
- Maintains list of request timestamps per client
- Cleans old entries every 100 requests
- Blocks client for remainder of window when exceeded

**Configuration**:
- Per-minute: 60 requests (default)
- Per-hour: 1000 requests (default)
- Block duration: Remainder of window

### 4. Input Validation

**Purpose**: Prevent injection attacks

**Patterns Detected**:
- SQL injection: `SELECT`, `UNION`, `--`, `;`
- Command injection: `&`, `|`, `$()`, backticks
- Path traversal: `../`, `..\`
- XSS: `<script>`, `javascript:`, event handlers

**Implementation**:
```python
DANGEROUS_PATTERNS = [
    r"(?i)(\b(union|select|insert|update|delete)\b.*\b(from|into)\b)",
    r"[;&|`$](\s*\w+)+",
    r"\.\./|\.\.\\",
    r"<script[^>]*>",
]
```

### 5. Audit Logging

**Purpose**: Forensic analysis and compliance

**Events Logged**:
- OAuth flows (registration, authorization, token exchange)
- Rate limit violations
- Tool calls (with redacted sensitive fields)
- IP-based access control decisions

**Log Format**:
```json
{
  "timestamp": "2024-01-01T00:00:00Z",
  "event_type": "tool_call",
  "client_id": "client_abc...",
  "user_id": "user_123",
  "ip_address": "a1b2c3d4...",  // SHA256 hashed
  "resource": "search_repositories",
  "action": "call",
  "success": true,
  "details": {
    "arguments": {"query": "mcp"},
    "result_summary": "Found 42 repositories"
  }
}
```

## Deployment Security

### HTTPS/TLS

**Development**: HTTP allowed on localhost
**Production**: TLS 1.2+ required

```bash
# Generate self-signed cert for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Configure
MCP_GATEWAY_SERVER__SSL_ENABLED=true
MCP_GATEWAY_SERVER__SSL_CERT_PATH=/path/to/cert.pem
MCP_GATEWAY_SERVER__SSL_KEY_PATH=/path/to/key.pem
```

### Secrets Management

**Never commit secrets to git!**

**Recommended approaches**:
1. Environment variables (via .env)
2. Cloud secret managers (AWS Secrets Manager, GCP Secret Manager)
3. HashiCorp Vault
4. Kubernetes Secrets

### Network Security

**Recommended architecture**:
```
                    ┌─────────────────┐
                    │   Load Balancer │
                    │   (TLS Termination)
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
        │  Gateway  │  │  Gateway  │  │  Gateway  │
        │  Instance │  │  Instance │  │  Instance │
        └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │      Redis      │
                    │  (Rate Limiting)│
                    └─────────────────┘
```

### Container Security

**Dockerfile best practices**:
- Use minimal base image (python:3.11-slim)
- Run as non-root user
- Multi-stage build for smaller image
- No secrets in image layers
- Health checks enabled

## Compliance Considerations

### SOC 2 Type II
- ✅ Access controls (OAuth)
- ✅ Audit logging
- ✅ Encryption in transit (TLS)
- ⚠️ Encryption at rest (configure database encryption)

### GDPR
- ✅ Data minimization (hashed IPs in logs)
- ✅ Purpose limitation (scope-based access)
- ⚠️ Data retention policy (configure log rotation)
- ⚠️ Right to erasure (implement user deletion)

### HIPAA
- ⚠️ BAA required for PHI
- ⚠️ Additional safeguards needed

## Security Checklist

### Development
- [ ] Use .env for secrets
- [ ] Add .env to .gitignore
- [ ] Enable debug logging
- [ ] Use localhost-only binding

### Staging
- [ ] Rotate all secrets from dev
- [ ] Enable TLS
- [ ] Configure audit logging
- [ ] Set up monitoring/alerting

### Production
- [ ] Use strong JWT secret (32+ bytes)
- [ ] Enable TLS 1.2+
- [ ] Configure IP allowlists
- [ ] Set up log aggregation
- [ ] Enable health checks
- [ ] Configure backup/DR
- [ ] Document incident response
- [ ] Regular security audits
- [ ] Penetration testing

## Incident Response

### Token Compromise
1. Revoke compromised tokens: `POST /oauth/revoke`
2. Rotate JWT secret
3. Force re-authorization for all clients
4. Audit logs for unauthorized access

### Backend Compromise
1. Disable backend: `unregister_backend(id)`
2. Rotate backend credentials
3. Audit tool calls via logs
4. Notify affected users

### Rate Limit Evasion
1. Identify pattern in logs
2. Add IP to blacklist
3. Contact abuse team
4. Consider CAPTCHA for registration

## Contact

Security issues: security@example.com
