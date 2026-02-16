import asyncio
from datetime import datetime
import json
import logging
import logging
import os
import aiohttp
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio

#Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('D:\\workspaces\\vscode\\aiml\\weather_server.log', mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ],
    force=True  # Force reconfiguration if already configured
)

# Get logger and set unbuffered output
logger = logging.getLogger(__name__)

# Force flush after each log
for handler in logging.root.handlers:
    if isinstance(handler, logging.FileHandler):
        handler.flush = lambda: handler.stream.flush() if handler.stream else None
        # Disable buffering on the file handler
        if handler.stream:
            handler.stream.reconfigure(line_buffering=True)

# Server declaration- Create an MCP server instance
server = Server("weather-server")

#VALID_AUTH_TOKEN = os.getenv("WEATHER_SERVER_AUTH_TOKEN")
VALID_AUTH_TOKEN = "1234"
AUTH_ENABLED = True  

def verify_auth(arguments: dict) -> tuple[bool, str]:
    """
    Verify authentication token from tool arguments.
    Returns (is_valid, error_message)
    """
    

    if not AUTH_ENABLED:
        logger.info("Authentication is disabled (no token configured)")
        return True, ""
    
    provided_token = arguments.get("auth_token")
    
    if not provided_token:
        logger.warning(f"Authentication failed: No token provided {VALID_AUTH_TOKEN}:{provided_token}")
        return False, "Authentication required. Please provide 'auth_token' parameter."
    
    if provided_token != VALID_AUTH_TOKEN:
        logger.warning(f"Authentication failed: Invalid token provided {VALID_AUTH_TOKEN}:{provided_token}")
        return False, "Authentication failed. Invalid token."
    
    logger.info("Authentication successful")
    return True, ""

# Define what tools your server provides
@server.list_tools()
async def list_tools() -> list[Tool]:
    """
    This function tells clients what tools are available.
    It returns metadata about each tool.
    """
    logger.info("Client requested list of available tools")
    for handler in logger.handlers:
        handler.flush()

    return [
        Tool(
            name="get_weather",
            description="Get current weather for a city",
            inputSchema={
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "description": "City name"
                    }
                },
                "required": ["city"]
            }
        )
    ]
    #logger.info(f"Returning {len(tools)} tool(s)")
    #return tools

# Tool implementaion- handles tool execution
@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    logger.info(f"Tool called: '{name}' with arguments: {arguments}")
    for handler in logger.handlers:
        handler.flush()

    """
    This function gets called when a client wants to use a tool.
    It receives the tool name and arguments, then returns results.
    """
    
    # Verify authentication first
    is_valid, error_msg = verify_auth(arguments)
    if not is_valid:
        logger.error(f"Authentication failed for tool '{name}'")
        for handler in logger.handlers:
            handler.flush()
        return [
            TextContent(
                type="text",
                text=json.dumps({
                    "error": error_msg,
                    "authenticated": False
                })
            )
        ]
    
    if name == "get_weather":
        city = arguments.get("city")
        api_key = "6e885f0deb9cfe26063d268c41fec4a7"
        
        try:
            logger.info(f"Fetching weather data for city: {city}")
            
            async with aiohttp.ClientSession() as session:
                url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}&units=imperial"
                logger.debug(f"API URL: {url.replace(api_key, 'HIDDEN')}")
                
                async with session.get(url) as response:
                    logger.info(f"API response status: {response.status}")
                    
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"API request failed: {error_text}")
                        raise Exception(f"Weather API returned status {response.status}")
                    
                    data = await response.json()
                    logger.debug(f"Raw API response: {json.dumps(data, indent=2)}")
                    

                    weather_data = {
                        "city": city,
                        "temperature": f"{data['main']['temp']}°F",
                        "condition": data['weather'][0]['description'],
                        "humidity": f"{data['main']['humidity']}%"
                    }
        
                    logger.info(f"Successfully retrieved weather for {city}: {weather_data['temperature']}, {weather_data['condition']}")
                    for handler in logger.handlers:
                        handler.flush()

        
                    return [
                        TextContent(
                            type="text",
                            text=json.dumps(weather_data, indent=2)
                        )
                    ]
    
        except Exception as e:
            logger.error(f"Error fetching weather for {city}: {str(e)}", exc_info=True)
            for handler in logger.handlers:
                handler.flush()
            return [
                TextContent(
                    type="text",
                    text=json.dumps({
                        "error": f"Failed to fetch weather: {str(e)}",
                        "city": city
                    })
                )
            ]
    else:
        logger.error(f"Unknown tool requested: {name}")
        raise ValueError(f"Unknown tool: {name}")   

# Main entry point
async def main():
    """
    Run the server using stdio transport.
    This means the server communicates via standard input/output.
    """
    logger.info("="*50)
    logger.info("Weather MCP Server Starting...")
    logger.info(f"Start time: {datetime.now().isoformat()}")
    logger.info(f"Authentication: {'ENABLED' if AUTH_ENABLED else 'DISABLED'}")
    logger.info("="*50)
    for handler in logger.handlers:
        handler.flush()

    try:
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            logger.info("Server initialized successfully")
            logger.info("Waiting for client connections...")
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options()
            )
    except Exception as e:
        logger.error(f"Server error: {str(e)}", exc_info=True)
        raise
    finally:
        logger.info("Weather MCP Server shutting down")


# Start the server
if __name__ == "__main__":
    asyncio.run(main())


"""
## Key Logging Features Added

### 1. **Log Levels**
- `INFO` - General information (server start, tool calls, successful operations)
- `DEBUG` - Detailed information (API URLs, raw responses)
- `ERROR` - Error conditions (API failures, exceptions)

### 2. **What Gets Logged**
- Server startup and shutdown
- Tool list requests
- Every tool call with arguments
- API requests and responses
- Success/failure of operations
- Full error stack traces

### 3. **Log Output**
Logs go to both:
- `weather_server.log` file in your server directory
- Console output (useful during development)
"""