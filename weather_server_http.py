import asyncio
from datetime import datetime
import json
import logging
import aiohttp
from aiohttp import web

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('weather_server_http.log', mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ],
    force=True
)

logger = logging.getLogger(__name__)

# Weather API configuration
WEATHER_API_KEY = "6e885f0deb9cfe26063d268c41fec4a7"

async def get_weather(city: str):
    """Fetch weather data from OpenWeatherMap API"""
    try:
        logger.info(f"Fetching weather data for city: {city}")
        
        async with aiohttp.ClientSession() as session:
            url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={WEATHER_API_KEY}&units=imperial"
            
            async with session.get(url) as response:
                logger.info(f"API response status: {response.status}")
                
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"API request failed: {error_text}")
                    return {"error": f"Weather API returned status {response.status}"}
                
                data = await response.json()
                
                weather_data = {
                    "city": city,
                    "temperature": f"{data['main']['temp']}°F",
                    "condition": data['weather'][0]['description'],
                    "humidity": f"{data['main']['humidity']}%",
                    "wind_speed": f"{data['wind']['speed']} mph"
                }
    
                logger.info(f"Successfully retrieved weather for {city}: {weather_data['temperature']}, {weather_data['condition']}")
                return weather_data

    except Exception as e:
        logger.error(f"Error fetching weather for {city}: {str(e)}", exc_info=True)
        return {"error": f"Failed to fetch weather: {str(e)}", "city": city}

# HTTP Handlers
async def handle_health(request):
    """Health check endpoint"""
    return web.json_response({
        "status": "healthy",
        "server": "weather-server",
        "timestamp": datetime.now().isoformat()
    })

async def handle_weather(request):
    """Get weather for a city"""
    try:
        data = await request.json()
        city = data.get("city")
        
        if not city:
            return web.json_response(
                {"error": "City parameter is required"},
                status=400
            )
        
        logger.info(f"Weather request for city: {city}")
        weather_data = await get_weather(city)
        
        return web.json_response({
            "success": "error" not in weather_data,
            "data": weather_data
        })
        
    except Exception as e:
        logger.error(f"Error handling weather request: {e}", exc_info=True)
        return web.json_response(
            {"error": str(e)},
            status=500
        )

async def handle_weather_get(request):
    """Get weather via GET request"""
    city = request.query.get("city")
    
    if not city:
        return web.json_response(
            {"error": "City parameter is required"},
            status=400
        )
    
    logger.info(f"Weather GET request for city: {city}")
    weather_data = await get_weather(city)
    
    return web.json_response({
        "success": "error" not in weather_data,
        "data": weather_data
    })

async def main():
    """Run the HTTP server"""
    logger.info("="*50)
    logger.info("Weather Server Starting (HTTP Mode)...")
    logger.info(f"Start time: {datetime.now().isoformat()}")
    logger.info("="*50)

    app = web.Application()
    
    # Add routes
    app.router.add_get("/health", handle_health)
    app.router.add_post("/weather", handle_weather)
    app.router.add_get("/weather", handle_weather_get)
    
    # Start server
    host = "0.0.0.0"
    port = 8080
    
    logger.info(f"Starting HTTP server on {host}:{port}")
    logger.info(f"Endpoints:")
    logger.info(f"  - http://{host}:{port}/health - Health check")
    logger.info(f"  - http://{host}:{port}/weather - Get weather (POST/GET)")
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
        logger.info("Weather Server shutting down")

if __name__ == "__main__":
    asyncio.run(main())
