from urllib.parse import urlparse

import requests
from fastmcp import FastMCP

mcp = FastMCP("url-allowlisted")


@mcp.tool()
def fetch_api(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname not in {"api.example.com"}:
        raise ValueError("Host is not approved")
    return requests.get(url, timeout=5).text
