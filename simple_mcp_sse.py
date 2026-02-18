#!/usr/bin/env python3
"""
Simple MCP Server - SSE Version for Render
Compatible with Claude Desktop
"""

import os
from fastmcp import FastMCP

# Create FastMCP server instance
mcp = FastMCP("simple-mcp-sse")

@mcp.tool()
def echo(text: str) -> str:
    """Echo back the input text
    
    Args:
        text: Text to echo back
    """
    return f"Echo: {text}"

@mcp.tool()
def add(a: float, b: float) -> str:
    """Add two numbers
    
    Args:
        a: First number
        b: Second number
    """
    result = a + b
    return f"Result: {result}"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting MCP SSE Server on port {port}")
    mcp.run(transport="sse")
