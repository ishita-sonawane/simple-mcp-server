#!/usr/bin/env python3
"""
Simple MCP Server v0.13 - HTTP Version
Basic implementation with network access
"""

import asyncio
from aiohttp import web

async def handle_health(request):
    """Health check endpoint"""
    return web.json_response({
        "status": "healthy",
        "server": "simple-mcp-v0.13",
        "tools": ["echo", "add"]
    })

async def handle_tools(request):
    """List available tools"""
    tools = [
        {
            "name": "echo",
            "description": "Echo back the input text",
            "parameters": {"text": "string"}
        },
        {
            "name": "add", 
            "description": "Add two numbers",
            "parameters": {"a": "number", "b": "number"}
        }
    ]
    return web.json_response({"tools": tools})

async def handle_call(request):
    """Execute a tool"""
    try:
        data = await request.json()
        tool = data.get("tool")
        args = data.get("arguments", {})
        
        if tool == "echo":
            text = args.get("text", "")
            return web.json_response({
                "success": True,
                "result": f"Echo: {text}"
            })
        
        elif tool == "add":
            a = args.get("a", 0)
            b = args.get("b", 0)
            result = a + b
            return web.json_response({
                "success": True,
                "result": f"Result: {result}"
            })
        
        else:
            return web.json_response({
                "success": False,
                "error": f"Unknown tool: {tool}"
            })
            
    except Exception as e:
        return web.json_response({
            "success": False,
            "error": str(e)
        })

async def main():
    """Start the HTTP server"""
    print("Simple MCP Server v0.13 - HTTP Version")
    print("="*40)
    
    app = web.Application()
    app.router.add_get("/health", handle_health)
    app.router.add_get("/tools", handle_tools)
    app.router.add_post("/call", handle_call)
    
    host = "0.0.0.0"
    port = 8084
    
    print(f"Server running on {host}:{port}")
    print(f"Endpoints:")
    print(f"  GET  /health - Health check")
    print(f"  GET  /tools  - List tools")
    print(f"  POST /call   - Execute tool")
    print("="*40)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        print("\nServer stopped")
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())