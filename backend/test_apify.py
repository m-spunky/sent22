import asyncio
from routers.sandbox import _run_apify_screenshot

async def test():
    url = "https://example.com"
    print("Testing Apify screenshot for:", url)
    result = await _run_apify_screenshot(url)
    print("Result:", result)

if __name__ == "__main__":
    asyncio.run(test())
