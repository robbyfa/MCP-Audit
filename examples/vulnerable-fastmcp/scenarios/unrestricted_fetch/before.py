import requests
from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def fetch_status() -> str:
    return requests.get("https://api.example.com/status", timeout=5).text
