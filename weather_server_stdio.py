import asyncio
import json
import logging
import sys
import os
from datetime import datetime

import aiohttp
from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio


# ==============================
# Logging Configuration
# ==============================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("weather_server.log", encoding="utf-8"),
        logging.StreamHandler(sys.stderr)  # IMPORTANT: stderr only
    ]
)

logger = logging.getLogger(__name__)


# ==============================
# Server Initialization
# ==============================

server = Server("weather-server")

# Optional authentication (set to False if not needed)
VALID_AUTH_TOKEN = "1234"
AUTH_ENABLED = False  # Set True if you want auth enforcement


def verify_auth(arguments: dict) -> tuple[bool, str]:
    if not AUTH_ENABLED:
        return True, ""

    provided_token = arguments.get("auth_token")

    if not provided_token:
        return False, "Authentication required. Provide 'auth_token'."

    if provided_token != VALID_AUTH_TOKEN:
        return False, "Invalid authentication token."

    return True, ""


# ==============================
# Tool Listing
# ==============================

@server.list_tools()
async def list_tools() -> list[Tool]:
    logger.info("Client requested available tools")

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


# ==============================
# Tool Execution
# ==============================

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    logger.info(f"Tool called: {name} | Arguments: {arguments}")

    is_valid, error_msg = verify_auth(arguments)
    if not is_valid:
        return [
            TextContent(
                type="text",
                text=json.dumps({"error": error_msg})
            )
        ]

    if name != "get_weather":
        raise ValueError(f"Unknown tool: {name}")

    city = arguments.get("city")
    if not city:
        return [
            TextContent(
                type="text",
                text=json.dumps({"error": "City is required"})
            )
        ]

    api_key = os.getenv("OPENWEATHER_API_KEY")

    if not api_key:
        return [
            TextContent(
                type="text",
                text=json.dumps({"error": "Missing OPENWEATHER_API_KEY environment variable"})
            )
        ]

    try:
        async with aiohttp.ClientSession() as session:
            url = (
                "http://api.openweathermap.org/data/2.5/weather"
                f"?q={city}&appid={api_key}&units=imperial"
            )

            async with session.get(url) as response:
                if response.status != 200:
                    return [
                        TextContent(
                            type="text",
                            text=json.dumps({
                                "error": f"Weather API returned status {response.status}"
                            })
                        )
                    ]

                data = await response.json()

                weather_data = {
                    "city": city,
                    "temperature": f"{data['main']['temp']}°F",
                    "condition": data['weather'][0]['description'],
                    "humidity": f"{data['main']['humidity']}%"
                }

                logger.info(f"Weather fetched successfully for {city}")

                return [
                    TextContent(
                        type="text",
                        text=json.dumps(weather_data, indent=2)
                    )
                ]

    except Exception as e:
        logger.exception("Weather fetch failed")
        return [
            TextContent(
                type="text",
                text=json.dumps({
                    "error": f"Failed to fetch weather: {str(e)}"
                })
            )
        ]


# ==============================
# Main Entry (STDIO)
# ==============================

async def main():
    logger.info("Weather MCP Server Starting (STDIO mode)")
    logger.info(f"Start time: {datetime.now().isoformat()}")

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
