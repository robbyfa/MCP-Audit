from urllib.parse import urlparse

import requests
from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def fetch_status(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname not in {"api.example.com"}:
        raise ValueError("host not approved")
    return requests.get(url, timeout=5).text
