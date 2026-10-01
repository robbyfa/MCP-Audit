from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("reports-demo")


@mcp.tool()
def read_report(path: str) -> str:
    return Path(path).read_text()
