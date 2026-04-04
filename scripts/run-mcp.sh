#!/bin/bash
# MCP Gateway MCP Server launcher
# This script runs the gateway in MCP stdio mode

cd /Users/rshetty/agentic-gateway

# Activate virtual environment and run MCP server
source venv/bin/activate
exec python -m gateway.server mcp