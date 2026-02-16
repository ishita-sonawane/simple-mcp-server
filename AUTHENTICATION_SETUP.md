# Weather MCP Server Authentication Setup

## How Authentication Works

The server uses environment variable-based authentication. When enabled, all tool calls require a valid `auth_token` parameter.

## Setup Instructions

### Step 1: Generate a Secure Token

Generate a random token (you can use any method):

**Windows PowerShell:**
```powershell
-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
```

**Or use a simple string:**
```
my-secret-token-12345
```

### Step 2: Configure Claude Desktop

Edit your Claude Desktop MCP configuration file:

**Location:** `%APPDATA%\Claude\claude_desktop_config.json`

**Add the environment variable:**

```json
{
  "mcpServers": {
    "weather-server": {
      "command": "python",
      "args": ["D:\\workspaces\\vscode\\aiml\\weather_server.py"],
      "env": {
        "WEATHER_SERVER_AUTH_TOKEN": "your-secret-token-here"
      }
    }
  }
}
```

### Step 3: Restart Claude Desktop

Close and reopen Claude Desktop completely for the changes to take effect.

## Usage

### With Authentication Enabled

When you ask Claude to check weather, it will need to provide the token:

```json
{
  "city": "Seattle",
  "auth_token": "your-secret-token-here"
}
```

Claude will automatically include this if configured properly.

### Without Authentication (Default)

If you don't set the `WEATHER_SERVER_AUTH_TOKEN` environment variable, the server runs without authentication (current behavior).

## Testing Authentication

1. **Test with auth enabled:**
   - Set the environment variable in config
   - Restart Claude Desktop
   - Ask: "What's the weather in Seattle?"
   - Check logs - should see "Authentication successful"

2. **Test with wrong token:**
   - Temporarily change the token in config
   - Restart Claude Desktop
   - Try to use the tool
   - Should get "Authentication failed" error

## Security Notes

- Keep your token secret - don't commit it to version control
- Use a strong, random token for production
- The token is passed in tool arguments (visible in logs)
- For local development, simple tokens are fine
- For production, consider more robust authentication methods

## Disabling Authentication

To disable authentication, simply remove the `WEATHER_SERVER_AUTH_TOKEN` from your environment variables in the Claude Desktop config.

## Troubleshooting

**"Authentication required" error:**
- Check that `WEATHER_SERVER_AUTH_TOKEN` is set in Claude config
- Restart Claude Desktop after config changes
- Check `weather_server.log` for authentication status

**Server won't start:**
- Verify the path to `weather_server.py` is correct
- Check that Python and dependencies are installed
- Look for errors in `weather_server.log`
