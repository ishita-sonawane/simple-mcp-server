# Simple MCP Server Project

## Overview

This project demonstrates building and testing Model Context Protocol (MCP) servers using Python. It includes both local (stdio) and remote (SSE) implementations of a simple MCP server with basic tools.

### What is MCP?

Model Context Protocol (MCP) is a standardized protocol that allows AI assistants (like Claude) to interact with external tools and data sources. MCP servers expose tools that AI models can discover and use.

### Project Objectives

1. Build a basic MCP server with simple tools (echo, add)
2. Test the server using MCP Inspector v0.14
3. Deploy the server remotely for testing purposes
4. Integrate with Claude Desktop for local usage

---

## Project Structure

```
mcp-servers/
├── simple_mcp_server.py      # Stdio MCP server (for Claude Desktop)
├── simple_mcp_sse.py          # SSE MCP server (for remote deployment)
├── simple_mcp_http.py         # Basic HTTP API (not MCP protocol)
├── requirements.txt           # Python dependencies
├── runtime.txt               # Python version for deployment
└── README.md                 # This file
```

---

## Prerequisites

- Python 3.13+ installed
- Node.js and npm installed (for MCP Inspector)
- Git installed
- Claude Desktop (optional, for local integration)
- Render or Vercel account (optional, for deployment)

---

## Part 1: Building the Simple MCP Server

### 1.1 Install Dependencies

```bash
pip install mcp starlette uvicorn sse-starlette
```

### 1.2 Understanding the Server Code

The `simple_mcp_server.py` implements:

- **Echo Tool**: Returns the input text with "Echo: " prefix
- **Add Tool**: Adds two numbers and returns the result

Key components:
```python
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio

# Create server instance
server = Server("simple-mcp")

# Define tools
@server.list_tools()
async def list_tools():
    # Returns list of available tools
    
@server.call_tool()
async def call_tool(name: str, arguments: dict):
    # Handles tool execution
```

### 1.3 Test the Server Locally

Run the server:
```bash
python simple_mcp_server.py
```

The server will wait for JSON-RPC messages on stdin. Test it:
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | python simple_mcp_server.py
```

Expected output: JSON response with server capabilities and tools.

---

## Part 2: Testing with MCP Inspector v0.14

### 2.1 What is MCP Inspector?

MCP Inspector is a web-based tool for testing and debugging MCP servers. It provides a UI to:
- Connect to MCP servers
- List available tools
- Execute tools with custom parameters
- View responses in real-time

### 2.2 Install and Run MCP Inspector

No installation needed - use npx:

```bash
npx @modelcontextprotocol/inspector@0.14.0
```

This will:
1. Download MCP Inspector v0.14
2. Start a local web server (usually http://localhost:5173)
3. Open the inspector in your browser

### 2.3 Connect Inspector to Your Server

**Option A: Auto-connect (recommended)**
```bash
npx @modelcontextprotocol/inspector@0.14.0 python simple_mcp_server.py
```

**Option B: Manual connection**
1. Run inspector: `npx @modelcontextprotocol/inspector@0.14.0`
2. In the UI, configure connection:
   - Transport: stdio
   - Command: `python`
   - Args: `simple_mcp_server.py`

### 2.4 Test the Tools

In the MCP Inspector UI:

1. **List Tools**: Click "List Tools" to see available tools
2. **Test Echo Tool**:
   - Select "echo" tool
   - Input: `{"text": "Hello MCP!"}`
   - Click "Execute"
   - Expected output: `"Echo: Hello MCP!"`

3. **Test Add Tool**:
   - Select "add" tool
   - Input: `{"a": 5, "b": 3}`
   - Click "Execute"
   - Expected output: `"Result: 8"`

---

## Part 3: Integrating with Claude Desktop

### 3.1 Configure Claude Desktop

Edit the config file:
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Mac/Linux**: `~/.config/Claude/claude_desktop_config.json`

Add your server:
```json
{
  "mcpServers": {
    "simple-mcp": {
      "command": "python",
      "args": ["D:\\path\\to\\simple_mcp_server.py"]
    }
  }
}
```

Replace the path with your actual file location.

### 3.2 Restart Claude Desktop

1. Completely quit Claude Desktop (check Task Manager on Windows)
2. Start Claude Desktop
3. Check Developer Settings to verify the server is connected

### 3.3 Use the Tools in Claude

In Claude Desktop, you can now ask:
- "Echo the text 'Hello World'"
- "Add 42 and 58"

Claude will automatically use your MCP server tools to respond.

---

## Part 4: Deploying to Render (Remote Testing)

### 4.1 Why Deploy Remotely?

Remote deployment allows:
- Testing from anywhere
- Sharing with team members
- Testing SSE transport (different from stdio)
- Simulating production environment

### 4.2 Prepare for Deployment

**Create requirements.txt:**
```txt
mcp
starlette
uvicorn
sse-starlette
```

**Create runtime.txt (optional):**
```txt
python-3.13.5
```

### 4.3 Push to GitHub

```bash
git init
git add simple_mcp_sse.py requirements.txt runtime.txt
git commit -m "Initial commit: Simple MCP SSE server"
git branch -M main
git remote add origin https://github.com/yourusername/simple-mcp-server.git
git push -u origin main
```

### 4.4 Deploy on Render

1. Go to https://dashboard.render.com
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: `simple-mcp-sse`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python simple_mcp_sse.py`
   - **Instance Type**: Free
5. Click "Create Web Service"
6. Wait 2-5 minutes for deployment

### 4.5 Test the Deployed Server

Get your Render URL (e.g., `https://simple-mcp-sse-xxxx.onrender.com`)

Test health endpoint:
```bash
curl https://your-app.onrender.com/health
```

Expected output: `OK`

### 4.6 Test with MCP Inspector

You can test the remote server using MCP Inspector, but note that Claude Desktop doesn't support remote SSE URLs directly.

---

## Troubleshooting

### Server Not Starting
- Check Python version: `python --version` (should be 3.13+)
- Verify dependencies: `pip list | grep mcp`
- Check for syntax errors in the server file

### Claude Desktop Not Showing Server
- Verify config file path and JSON syntax
- Use absolute paths in the config
- Completely quit and restart Claude Desktop
- Check that Python path is correct

### MCP Inspector Connection Failed
- Ensure server file path is correct
- Check that Python is in your PATH
- Try running the server manually first to check for errors

### Render Deployment Failed
- Check Render logs for specific errors
- Verify requirements.txt includes all dependencies
- Ensure server binds to `0.0.0.0` not `localhost`
- Check that PORT environment variable is used

---

## Key Concepts

### MCP Protocol Version
- This project uses MCP protocol version `2024-11-05`
- Python MCP library version: `1.26.0`

### Transport Types
- **stdio**: Standard input/output (for local tools like Claude Desktop)
- **SSE**: Server-Sent Events over HTTP (for remote servers)
- **HTTP**: Basic HTTP API (not MCP protocol)

### Tool Schema
Tools are defined with JSON Schema for parameters:
```python
Tool(
    name="echo",
    description="Echo back the input text",
    inputSchema={
        "type": "object",
        "properties": {
            "text": {"type": "string"}
        },
        "required": ["text"]
    }
)
```

---

## Next Steps

1. **Add More Tools**: Extend the server with additional functionality
2. **Add Authentication**: Implement API key authentication for remote servers
3. **Add Resources**: Expose data sources (files, databases) via MCP
4. **Add Prompts**: Define reusable prompt templates
5. **Error Handling**: Improve error messages and validation
6. **Logging**: Add comprehensive logging for debugging

---

## Resources

- [MCP Documentation](https://modelcontextprotocol.io)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [MCP Inspector](https://github.com/modelcontextprotocol/inspector)
- [Claude Desktop](https://claude.ai/download)

---

## License

MIT License - Feel free to use and modify for your projects.

---

## Version History

- **v0.13**: Initial simple MCP server with echo and add tools
- **v0.14**: Added SSE support for remote deployment
- **v1.0**: Production-ready with documentation

---

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## Support

For issues or questions:
- Check the troubleshooting section
- Review MCP documentation
- Open an issue on GitHub
