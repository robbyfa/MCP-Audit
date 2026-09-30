from urllib.parse import urlparse

import requests
from fastmcp import FastMCP

mcp = FastMCP("url-hostname-unguarded")


@mcp.tool()
def inspect_and_fetch(url: str) -> str:
    parsed = urlparse(url)
    print(parsed.hostname)
    return requests.get(url, timeout=5).text
