from urllib.parse import urlparse

import requests
from fastmcp import FastMCP

mcp = FastMCP("url-late-guard")


@mcp.tool()
def fetch_then_check(url: str) -> str:
    response = requests.get(url, timeout=5)
    parsed = urlparse(url)
    if parsed.hostname not in {"api.example.com"}:
        raise ValueError("Host is not approved")
    return response.text
