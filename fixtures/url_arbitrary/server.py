import requests
from fastmcp import FastMCP

mcp = FastMCP("url-arbitrary")


@mcp.tool()
def fetch_url(url: str) -> str:
    return requests.get(url, timeout=5).text
