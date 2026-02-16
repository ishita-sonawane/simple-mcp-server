#!/usr/bin/env python3
"""
Vulnerable Notes MCP Server - HTTP Version
FOR SECURITY TESTING PURPOSES ONLY
"""

import asyncio
import logging
import json
from typing import Any
from datetime import datetime
from aiohttp import web

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('notes_server_http.log', mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ],
    force=True
)

logger = logging.getLogger(__name__)

# Simple storage
notes = {}
next_id = 1

# Tool handlers
async def handle_add(arguments):
    """Add two numbers"""
    result = arguments["a"] + arguments["b"]
    return {"result": result, "message": f"Result: {result}"}

async def handle_create_note(arguments):
    """Create a note"""
    global next_id
    notes[next_id] = arguments["text"]
    note_id = next_id
    next_id += 1
    return {"note_id": note_id, "message": f"Note created! ID: {note_id}"}

async def handle_search(arguments):
    """Search notes - VULNERABLE to code injection"""
    query = arguments["query"]
    
    # VULNERABILITY: Code injection via eval
    if "eval:" in query:
        try:
            result = eval(query.replace("eval:", ""))
            return {"result": str(result), "message": f"Eval result: {result}"}
        except Exception as e:
            return {"error": str(e)}
    
    # Normal search
    found = [f"ID {i}: {n}" for i, n in notes.items() if query in n]
    return {"results": found, "message": "\n".join(found) if found else "No results"}

async def handle_run_command(arguments):
    """Run system command - VULNERABLE to command injection"""
    cmd = arguments["cmd"]
    
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=5)
        
        return {
            "stdout": out.decode(),
            "stderr": err.decode(),
            "returncode": proc.returncode,
            "message": f"Command executed: {cmd}"
        }
    except asyncio.TimeoutError:
        return {"error": "Command timed out"}
    except Exception as e:
        return {"error": str(e)}

async def handle_login(arguments):
    """Login - VULNERABLE to SQL injection and hardcoded credentials"""
    user = arguments["user"]
    pwd = arguments["pass"]
    
    # Simulated SQL query - VULNERABILITY: SQL injection
    query = f"SELECT * FROM users WHERE user='{user}' AND pass='{pwd}'"
    logger.info(f"Auth query: {query}")
    
    # SQL injection bypass
    if "' OR '1'='1" in user or "' OR '1'='1" in pwd:
        return {"authenticated": True, "role": "admin", "message": "✓ Admin access granted! (SQL Injection)"}
    
    # VULNERABILITY: Hardcoded credentials
    if user == "admin" and pwd == "admin123":
        return {"authenticated": True, "role": "admin", "message": "✓ Logged in as admin"}
    
    return {"authenticated": False, "message": "✗ Login failed"}

# Tool registry
TOOLS = {
    "add": handle_add,
    "create_note": handle_create_note,
    "search": handle_search,
    "run_command": handle_run_command,
    "login": handle_login
}

# HTTP Handlers
async def handle_health(request):
    """Health check endpoint"""
    return web.json_response({
        "status": "healthy",
        "server": "vulnerable-notes-mcp",
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": [
            "Code injection via eval",
            "Command injection",
            "SQL injection",
            "Hardcoded credentials"
        ],
        "tools": list(TOOLS.keys())
    })

async def handle_tools_list(request):
    """List available tools"""
    tools = [
        {
            "name": "add",
            "description": "Add two numbers",
            "parameters": {"a": "integer", "b": "integer"}
        },
        {
            "name": "create_note",
            "description": "Create a note",
            "parameters": {"text": "string"}
        },
        {
            "name": "search",
            "description": "Search notes (use eval: for code execution)",
            "parameters": {"query": "string"}
        },
        {
            "name": "run_command",
            "description": "Run system command",
            "parameters": {"cmd": "string"}
        },
        {
            "name": "login",
            "description": "Login with username/password",
            "parameters": {"user": "string", "pass": "string"}
        }
    ]
    
    return web.json_response({"tools": tools})

async def handle_tool_call(request):
    """Execute a tool"""
    try:
        data = await request.json()
        tool_name = data.get("tool")
        arguments = data.get("arguments", {})
        
        logger.info(f"Tool called: {tool_name} with args: {arguments}")
        
        if tool_name not in TOOLS:
            return web.json_response(
                {"error": f"Unknown tool: {tool_name}"},
                status=400
            )
        
        # Execute tool
        result = await TOOLS[tool_name](arguments)
        
        return web.json_response({
            "tool": tool_name,
            "success": True,
            "result": result
        })
        
    except Exception as e:
        logger.error(f"Error executing tool: {e}", exc_info=True)
        return web.json_response(
            {"error": str(e), "success": False},
            status=500
        )

async def handle_notes_list(request):
    """List all notes"""
    return web.json_response({
        "notes": notes,
        "count": len(notes)
    })

async def main():
    """Run the HTTP server"""
    logger.info("="*50)
    logger.info("Vulnerable Notes Server Starting (HTTP Mode)...")
    logger.info("FOR SECURITY TESTING ONLY")
    logger.info("="*50)

    app = web.Application()
    
    # Add routes
    app.router.add_get("/health", handle_health)
    app.router.add_get("/tools", handle_tools_list)
    app.router.add_post("/call", handle_tool_call)
    app.router.add_get("/notes", handle_notes_list)
    
    # Start server
    host = "0.0.0.0"
    port = 8081
    
    logger.info(f"Starting HTTP server on {host}:{port}")
    logger.info(f"Endpoints:")
    logger.info(f"  - http://{host}:{port}/health - Health check")
    logger.info(f"  - http://{host}:{port}/tools - List tools")
    logger.info(f"  - http://{host}:{port}/call - Execute tool")
    logger.info(f"  - http://{host}:{port}/notes - List notes")
    logger.info("Server is accessible from other devices on the network")
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    
    logger.info("Server started successfully!")
    
    # Keep running
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    finally:
        await runner.cleanup()
        logger.info("Server shutting down")

if __name__ == "__main__":
    asyncio.run(main())
