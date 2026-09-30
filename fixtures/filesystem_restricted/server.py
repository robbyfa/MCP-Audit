from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("filesystem-restricted")
WORKSPACE_ROOT = Path("/srv/reports").resolve()


@mcp.tool()
def read_report(path: str) -> str:
    resolved = (WORKSPACE_ROOT / path).resolve()
    if WORKSPACE_ROOT not in resolved.parents:
        raise ValueError("Path escapes report root")
    return resolved.read_text()
