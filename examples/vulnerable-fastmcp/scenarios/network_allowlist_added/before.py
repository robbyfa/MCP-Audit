import requests
from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def fetch_status(url: str) -> str:
    return requests.get(url, timeout=5).text
