#!/usr/bin/env python3
"""
Simple MCP Server v0.13
Basic implementation with essential functionality
"""

import asyncio
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio

# Create server instance
server = Server("simple-mcp")

@server.list_tools()
async def list_tools():
    """List available tools"""
    return [
        Tool(
            name="echo",
            description="Echo back the input text",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to echo back"
                    }
                },
                "required": ["text"]
            }
        ),
        Tool(
            name="add",
            description="Add two numbers",
            inputSchema={
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"}
                },
                "required": ["a", "b"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """Handle tool calls"""
    if name == "echo":
        text = arguments.get("text", "")
        return [TextContent(type="text", text=f"Echo: {text}")]
    
    elif name == "add":
        a = arguments.get("a", 0)
        b = arguments.get("b", 0)
        result = a + b
        return [TextContent(type="text", text=f"Result: {result}")]
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def main():
    """Main server function"""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())