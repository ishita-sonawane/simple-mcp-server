#!/usr/bin/env python3
"""
Simple Vulnerable MCP Server - FOR TESTING ONLY
DO NOT USE IN PRODUCTION
"""

import asyncio
import logging
from typing import Any
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio

# Log to file and console for better debugging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnerable_notes_server.log', mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ],
    force=True
)

# Enable line buffering for immediate log writes
for handler in logging.root.handlers:
    if isinstance(handler, logging.FileHandler):
        if handler.stream:
            handler.stream.reconfigure(line_buffering=True)

logger = logging.getLogger(__name__)

# Simple storage
notes = {}
next_id = 1

server = Server("notes")

@server.list_tools()
async def list_tools() -> list[Tool]:
    try:
        logger.info("Client requested tool list")
        return [
        Tool(
            name="create_note",
            description="Create a note",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string"}
                },
                "required": ["text"]
            }
        ),
        Tool(
            name="search",
            description="Search notes (use eval: for code)",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"}
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="run_command",
            description="Run system command",
            inputSchema={
                "type": "object",
                "properties": {
                    "cmd": {"type": "string"}
                },
                "required": ["cmd"]
            }
        ),
        Tool(
            name="login",
            description="Login with username/password",
            inputSchema={
                "type": "object",
                "properties": {
                    "user": {"type": "string"},
                    "pass": {"type": "string"}
                },
                "required": ["user", "pass"]
            }
        )
    ]
    except Exception as e:
        logger.error(f"Error in list_tools: {e}", exc_info=True)
        return []

@server.call_tool()
async def call_tool(name: str, arguments: Any):
    global next_id
    
    logger.info(f"Tool called: {name} with args: {arguments}")
    
    try:
        # Simple calculator
        if name == "add":
            result = arguments["a"] + arguments["b"]
            return [TextContent(type="text", text=f"Result: {result}")]
        
        # Create note
        elif name == "create_note":
            notes[next_id] = arguments["text"]
            next_id += 1
            return [TextContent(type="text", text=f"Note created! ID: {next_id-1}")]
        
        # VULNERABILITY: Code injection
        elif name == "search":
            query = arguments["query"]
            
            if "eval:" in query:
                result = eval(query.replace("eval:", ""))
                return [TextContent(type="text", text=f"Result: {result}")]
            
            found = [f"ID {i}: {n}" for i, n in notes.items() if query in n]
            return [TextContent(type="text", text="\n".join(found) if found else "No results")]
        
        # VULNERABILITY: Command injection
        elif name == "run_command":
            proc = await asyncio.create_subprocess_shell(
                arguments["cmd"],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=5)
            return [TextContent(type="text", text=f"Output:\n{out.decode()}\n\nError:\n{err.decode()}")]
        
        # VULNERABILITY: SQL injection + hardcoded password
        elif name == "login":
            user = arguments["user"]
            pwd = arguments["pass"]
            
            # Simulated SQL query
            query = f"SELECT * FROM users WHERE user='{user}' AND pass='{pwd}'"
            logger.info(f"Auth query: {query}")
            
            # SQL injection bypass
            if "' OR '1'='1" in user or "' OR '1'='1" in pwd:
                return [TextContent(type="text", text="✓ Admin access granted!")]
            
            # Hardcoded password
            if user == "admin" and pwd == "admin123":
                return [TextContent(type="text", text="✓ Logged in as admin")]
            
            return [TextContent(type="text", text="✗ Login failed")]
        
        return [TextContent(type="text", text="Unknown tool")]
        
    except Exception as e:
        logger.error(f"Error in call_tool: {e}", exc_info=True)
        return [TextContent(type="text", text=f"Error: {e}")]

async def main():
    logging.info("Starting server...")
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())