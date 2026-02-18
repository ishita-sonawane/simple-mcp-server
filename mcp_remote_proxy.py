#!/usr/bin/env python3
"""
MCP Remote Proxy - Connects stdio to remote SSE server
Allows Claude Desktop to use remote MCP servers
"""

import sys
import json
import asyncio
import httpx
from typing import Any

REMOTE_SERVER_URL = "https://simple-mcp-server-qkg6.onrender.com"

async def forward_to_remote(message: dict) -> dict:
    """Forward message to remote SSE server"""
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{REMOTE_SERVER_URL}/message",
            json=message
        )
        return response.json()

async def main():
    """Main proxy loop"""
    while True:
        try:
            # Read from stdin
            line = await asyncio.get_event_loop().run_in_executor(
                None, sys.stdin.readline
            )
            
            if not line:
                break
                
            # Parse JSON-RPC message
            message = json.loads(line.strip())
            
            # Forward to remote server
            response = await forward_to_remote(message)
            
            # Write response to stdout
            print(json.dumps(response), flush=True)
            
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": message.get("id") if 'message' in locals() else None,
                "error": {
                    "code": -32603,
                    "message": str(e)
                }
            }
            print(json.dumps(error_response), flush=True)

if __name__ == "__main__":
    asyncio.run(main())
