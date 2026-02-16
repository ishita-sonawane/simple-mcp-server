# Network-Accessible MCP Servers for Security Testing

## Overview

I've created HTTP versions of your MCP servers that are accessible over the network for security testing from other devices.

## Servers Created

### 1. Weather Server (HTTP)
- **File**: `weather_server_http.py`
- **Port**: 8080
- **Endpoints**:
  - `http://YOUR_IP:8080/sse` - SSE endpoint for MCP
  - `http://YOUR_IP:8080/health` - Health check

### 2. Notes Server (HTTP)
- **File**: `notes_server_http.py`
- **Port**: 8081
- **Endpoints**:
  - `http://YOUR_IP:8081/sse` - SSE endpoint for MCP
  - `http://YOUR_IP:8081/health` - Health check

## Setup Instructions

### Step 1: Install Dependencies

```cmd
pip install aiohttp mcp
```

### Step 2: Find Your IP Address

```cmd
ipconfig
```

Look for "IPv4 Address" under your active network adapter (e.g., 192.168.1.100)

### Step 3: Start the Servers

**Terminal 1 - Weather Server:**
```cmd
python weather_server_http.py
```

**Terminal 2 - Notes Server:**
```cmd
python notes_server_http.py
```

### Step 4: Configure Firewall

Allow incoming connections on ports 8080 and 8081:

```cmd
netsh advfirewall firewall add rule name="MCP Weather Server" dir=in action=allow protocol=TCP localport=8080
netsh advfirewall firewall add rule name="MCP Notes Server" dir=in action=allow protocol=TCP localport=8081
```

## Testing from Another Device

### Health Check Test

From another device on the same network:

```bash
# Weather server
curl http://YOUR_IP:8080/health

# Notes server
curl http://YOUR_IP:8081/health
```

Replace `YOUR_IP` with your actual IP address (e.g., 192.168.1.100)

### MCP Client Test

You can use any MCP client to connect to:
- Weather: `http://YOUR_IP:8080/sse`
- Notes: `http://YOUR_IP:8081/sse`

## Security Testing Targets

### Weather Server
- Authentication bypass (currently disabled)
- API key exposure
- Input validation

### Notes Server (Intentionally Vulnerable)

1. **Code Injection**
   - Tool: `search`
   - Payload: `{"query": "eval:__import__('os').system('whoami')"}`

2. **Command Injection**
   - Tool: `run_command`
   - Payload: `{"cmd": "dir & whoami"}`

3. **SQL Injection**
   - Tool: `login`
   - Payload: `{"user": "admin' OR '1'='1", "pass": "anything"}`

4. **Hardcoded Credentials**
   - Tool: `login`
   - Credentials: `{"user": "admin", "pass": "admin123"}`

## Example Attack Scenarios

### 1. Remote Code Execution via Search

```bash
curl -X POST http://YOUR_IP:8081/messages \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "search",
      "arguments": {
        "query": "eval:__import__('os').listdir('.')"
      }
    },
    "id": 1
  }'
```

### 2. Command Injection

```bash
curl -X POST http://YOUR_IP:8081/messages \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "run_command",
      "arguments": {
        "cmd": "whoami"
      }
    },
    "id": 1
  }'
```

### 3. Authentication Bypass

```bash
curl -X POST http://YOUR_IP:8081/messages \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "login",
      "arguments": {
        "user": "admin'\'' OR '\''1'\''='\''1",
        "pass": "anything"
      }
    },
    "id": 1
  }'
```

## Network Access

### Same Network
- Both devices must be on the same network (WiFi/LAN)
- Use the local IP address (192.168.x.x or 10.x.x.x)

### Different Networks (Advanced)
- Set up port forwarding on your router
- Use your public IP address
- **WARNING**: This exposes vulnerable servers to the internet!

## Monitoring

### Check Logs

**Weather Server:**
```cmd
type weather_server_http.log
```

**Notes Server:**
```cmd
type notes_server_http.log
```

### Real-time Monitoring

```cmd
# Windows PowerShell
Get-Content weather_server_http.log -Wait
Get-Content notes_server_http.log -Wait
```

## Stopping the Servers

Press `Ctrl+C` in each terminal window running the servers.

## Security Notes

⚠️ **IMPORTANT**:
- These servers are intentionally vulnerable
- Only use on isolated test networks
- Never expose to the public internet
- Disable firewall rules after testing
- The notes server contains multiple critical vulnerabilities

## Differences from stdio Version

| Feature | stdio (Original) | HTTP (New) |
|---------|------------------|------------|
| Network Access | No | Yes |
| Port | None | 8080/8081 |
| Remote Testing | No | Yes |
| Claude Desktop | Yes | No* |
| Security | More secure | Less secure |

*HTTP version can be used with Claude Desktop by configuring SSE transport, but that's more complex.

## Troubleshooting

### "Connection refused"
- Check if server is running
- Verify firewall rules
- Confirm correct IP address

### "Cannot access from other device"
- Ensure both devices on same network
- Check Windows Firewall settings
- Try disabling firewall temporarily for testing

### "Port already in use"
- Change port numbers in the Python files
- Update firewall rules accordingly

## Clean Up After Testing

```cmd
# Remove firewall rules
netsh advfirewall firewall delete rule name="MCP Weather Server"
netsh advfirewall firewall delete rule name="MCP Notes Server"

# Stop servers
# Press Ctrl+C in each terminal
```
