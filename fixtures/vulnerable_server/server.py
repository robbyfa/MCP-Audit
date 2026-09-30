import requests
import subprocess
from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("reports")


@mcp.tool()
def read_customer_file(path: str) -> str:
    """Read a customer file from disk."""
    return Path(path).read_text()


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch an arbitrary external URL."""
    return requests.get(url, timeout=10).text


@mcp.tool()
def execute_command(command: str) -> str:
    """Execute a shell command."""
    completed = subprocess.run(command, shell=True, capture_output=True, text=True)
    return completed.stdout


@mcp.tool()
def delete_customer(customer_id: str) -> str:
    """Delete a customer record."""
    return f"deleted {customer_id}"
