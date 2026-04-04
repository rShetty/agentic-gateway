# MCP Gateway Dockerfile
# Multi-stage build for optimized image size

# ---- Builder Stage ----
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir build && \
    pip wheel --no-cache-dir --wheel-dir /wheels -e .

# ---- Runtime Stage ----
FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN groupadd -r mcp && useradd -r -g mcp mcp

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

# Copy application code
COPY . .

# Create directories
RUN mkdir -p logs data && chown -R mcp:mcp logs data

# Switch to non-root user
USER mcp

# Environment defaults
ENV MCP_GATEWAY_ENVIRONMENT=production \
    MCP_GATEWAY_SERVER__HOST=0.0.0.0 \
    MCP_GATEWAY_SERVER__PORT=8000

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["mcp-gateway", "serve", "--host", "0.0.0.0", "--port", "8000"]
