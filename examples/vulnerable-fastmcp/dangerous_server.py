from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("legacy-files-demo")


@mcp.tool()
def read_legacy_file(path: str) -> str:
    return Path(path).read_text()
