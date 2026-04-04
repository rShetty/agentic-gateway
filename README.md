# MCP Gateway

**OAuth-authenticated MCP proxy for connecting MCP clients to third-party services.**

An MCP Gateway acts as a middle layer between MCP clients (like Cursor, Claude Code, Windsurf) and third-party services. It provides:

- **OAuth 2.1 Authentication** with PKCE for secure client authentication
- **Backend Aggregation** - Connect to MCP servers OR direct APIs
- **Security Layer** - Rate limiting, input validation, audit logging
- **Tool Discovery** - Automatic aggregation of tools from all backends

## Architecture

```
┌─────────────────┐                    ┌──────────────────┐                    ┌─────────────────┐
│   MCP Client    │                    │   MCP Gateway    │                    │    Backends     │
│ (Cursor/Claude) │                    │                  │                    │                 │
│                 │   OAuth + MCP      │                  │    MCP or API      │                 │
│  ┌───────────┐  │ ◄─────────────────►│  ┌────────────┐  │ ◄─────────────────►│  ┌───────────┐  │
│  │  MCP SDK  │  │                    │  │  FastMCP   │  │                    │  │  GitHub   │  │
│  └───────────┘  │                    │  └────────────┘  │                    │  │  Slack    │  │
│                 │                    │                  │                    │  │  OpenAI   │  │
│                 │                    │  ┌────────────┐  │                    │  │  Linear   │  │
│                 │                    │  │   OAuth    │  │                    │  └───────────┘  │
│                 │                    │  └────────────┘  │                    │                 │
│                 │                    │                  │                    │                 │
│                 │                    │  ┌────────────┐  │                    │                 │
│                 │                    │  │  Security  │  │                    │                 │
│                 │                    │  └────────────┘  │                    │                 │
└─────────────────┘                    └──────────────────┘                    └─────────────────┘
```

## Quick Start

### 1. Install

```bash
cd mcp-gateway
pip install -e .
```

### 2. Configure Environment

```bash
# Create .env file
cat > .env << EOF
# Server
MCP_GATEWAY_ENVIRONMENT=development
SERVER_PORT=8000

# OAuth (auto-generated in dev, set explicitly for production)
OAUTH_JWT_SECRET_KEY=your-secret-key-here

# Backend credentials (optional, for backend auth)
GITHUB_PERSONAL_ACCESS_TOKEN=ghp_xxx
OPENAI_API_KEY=sk-xxx
SLACK_BOT_TOKEN=xoxb-xxx

# Security
SECURITY_RATE_LIMIT_REQUESTS_PER_MINUTE=60
SECURITY_AUDIT_ENABLED=true
EOF
```

### 3. Start the Server

**HTTP Mode (for web/REST access):**
```bash
mcp-gateway serve --port 8000
```

**MCP Mode (for MCP client connection):**
```bash
mcp-gateway mcp
```

### 4. Register an OAuth Client

```bash
mcp-gateway register-client \
  --name "My Cursor" \
  --redirect-uri "cursor://oauth/callback"
```

Output:
```
Client registered successfully!
  Client ID: client_ABC123...
  Client Name: My Cursor
  Redirect URIs: ['cursor://oauth/callback']
```

### 5. Authorize the Client

```bash
mcp-gateway authorize \
  --client-id client_ABC123... \
  --redirect-uri "cursor://oauth/callback" \
  --output tokens.json
```

This will:
1. Generate PKCE code verifier/challenge
2. Open the authorization URL
3. Prompt for the authorization code
4. Exchange the code for access/refresh tokens
5. Save tokens to `tokens.json`

### 6. Use the Gateway

```bash
# List available backends
mcp-gateway list-backends --token YOUR_ACCESS_TOKEN

# Call a tool
mcp-gateway call \
  --tool search_repositories \
  --arguments '{"query": "mcp gateway"}' \
  --token YOUR_ACCESS_TOKEN
```

## Connecting MCP Clients

### Cursor

Add to your Cursor MCP settings:

```json
{
  "mcpServers": {
    "gateway": {
      "url": "http://localhost:8000/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_ACCESS_TOKEN"
      }
    }
  }
}
```

### Claude Code (Claude Desktop)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "gateway": {
      "command": "mcp-gateway",
      "args": ["mcp"],
      "env": {
        "OAUTH_JWT_SECRET_KEY": "your-secret-key",
        "MCP_GATEWAY_ENVIRONMENT": "production"
      }
    }
  }
}
```

### Windsurf / VS Code Extensions

Configure the MCP endpoint:

```
Endpoint: http://localhost:8000/mcp
Headers:
  Authorization: Bearer YOUR_ACCESS_TOKEN
```

## Security Features

### OAuth 2.1 with PKCE

The gateway implements the full OAuth 2.1 specification with PKCE for public clients:

1. **Client Registration** - Register your app with redirect URIs
2. **Authorization Code Flow** - User grants access via authorization code
3. **PKCE** - Code challenge prevents authorization code interception
4. **JWT Tokens** - Short-lived access tokens with refresh token rotation

### Rate Limiting

- **Per-minute limit**: 60 requests (configurable)
- **Per-hour limit**: 1000 requests (configurable)
- **Sliding window** algorithm for accurate limiting
- **Automatic blocking** with Retry-After headers

### Input Validation

- **SQL injection detection** - Blocks SQL-like patterns
- **Command injection detection** - Blocks shell metacharacters
- **Path traversal prevention** - Blocks `../` patterns
- **XSS prevention** - HTML sanitization
- **Size limits** - Max request size and string length

### Audit Logging

All security-relevant events are logged:

- OAuth flows (registration, authorization, token exchange)
- Rate limit violations
- Tool calls (with redacted sensitive fields)
- IP-based access control

Logs include:
- Timestamp
- Event type
- Client/user IDs
- IP address (hashed for privacy)
- Success/failure status

## Backend Configuration

### MCP Server Backends

```yaml
# In config/backends.yaml
backends:
  github:
    type: mcp
    name: GitHub
    description: GitHub API via MCP server
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-github"
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: ${GITHUB_PAT}
    tools:
      - create_issue
      - create_pull_request
      - search_repositories
    requires_auth: true
```

### API Backends

```yaml
backends:
  openai:
    type: api
    name: OpenAI
    base_url: https://api.openai.com/v1
    auth_type: bearer
    env_key: OPENAI_API_KEY
    tools:
      - chat_completions
      - embeddings
    requires_auth: true
```

## API Reference

### OAuth Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/register` | POST | Register a new OAuth client |
| `/oauth/authorize` | GET | Authorization endpoint (consent page) |
| `/oauth/token` | POST | Token endpoint (exchange code for tokens) |
| `/oauth/revoke` | POST | Revoke an access or refresh token |

### MCP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp/backends` | GET | List all backends and their status |
| `/mcp/backends/{id}/connect` | POST | Connect to a specific backend |
| `/mcp/tools` | GET | List all available tools |
| `/mcp/call` | POST | Call a tool on a backend |

### MCP Tools (via FastMCP)

When connected via MCP, the following tools are available:

| Tool | Description |
|------|-------------|
| `gateway_list_backends` | List all backend services |
| `gateway_list_tools` | List all available tools |
| `gateway_call_tool` | Call a tool on a backend |
| `gateway_connect_backend` | Connect to a backend |

## Configuration Reference

### Environment Variables

All configuration can be set via environment variables with the `MCP_GATEWAY_` prefix:

```bash
# Server
MCP_GATEWAY_ENVIRONMENT=development|staging|production
MCP_GATEWAY_SERVER__HOST=0.0.0.0
MCP_GATEWAY_SERVER__PORT=8000
MCP_GATEWAY_DEBUG=true

# OAuth
MCP_GATEWAY_OAUTH__JWT_SECRET_KEY=your-secret-key
MCP_GATEWAY_OAUTH__ACCESS_TOKEN_EXPIRE_MINUTES=30
MCP_GATEWAY_OAUTH__REFRESH_TOKEN_EXPIRE_DAYS=7

# Security
MCP_GATEWAY_SECURITY__RATE_LIMIT_REQUESTS_PER_MINUTE=60
MCP_GATEWAY_SECURITY__RATE_LIMIT_REQUESTS_PER_HOUR=1000
MCP_GATEWAY_SECURITY__AUDIT_ENABLED=true
MCP_GATEWAY_SECURITY__AUDIT_LOG_PATH=logs/audit.log

# Backend
MCP_GATEWAY_BACKEND__CONNECT_TIMEOUT_SECONDS=30
MCP_GATEWAY_BACKEND__TOOL_TIMEOUT_SECONDS=120
```

## Production Deployment

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install -e .

EXPOSE 8000

CMD ["mcp-gateway", "serve", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t mcp-gateway .
docker run -p 8000:8000 \
  -e MCP_GATEWAY_OAUTH__JWT_SECRET_KEY=your-secret-key \
  -e MCP_GATEWAY_ENVIRONMENT=production \
  mcp-gateway
```

### Kubernetes

See `deploy/kubernetes/` for Helm charts and deployment manifests.

### Security Checklist

For production deployment:

- [ ] Set strong `OAUTH_JWT_SECRET_KEY` (use `openssl rand -hex 32`)
- [ ] Enable TLS/SSL (`SERVER__SSL_ENABLED=true`)
- [ ] Configure `IP_WHITELIST` if needed
- [ ] Set up audit log aggregation
- [ ] Configure rate limits appropriately
- [ ] Use Redis for distributed rate limiting
- [ ] Set up health checks and monitoring
- [ ] Rotate credentials regularly

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Style

```bash
black .
ruff check .
mypy .
```

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please read CONTRIBUTING.md for guidelines.

## Related Projects

- [MCP Specification](https://modelcontextprotocol.io) - The Model Context Protocol
- [Hermes Agent](https://github.com/nousresearch/hermes-agent) - The AI agent framework this is based on
- [FastMCP](https://github.com/anthropics/mcp) - The MCP SDK used

## Support

For issues and feature requests, please open a GitHub issue.
