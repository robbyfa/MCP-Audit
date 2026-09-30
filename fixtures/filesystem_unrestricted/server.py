from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("filesystem-unrestricted")


@mcp.tool()
def read_file(path: str) -> str:
    return Path(path).read_text()
