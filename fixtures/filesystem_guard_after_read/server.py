from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("filesystem-late-guard")
WORKSPACE_ROOT = Path("/srv/reports").resolve()


@mcp.tool()
def read_then_check(path: str) -> str:
    resolved = (WORKSPACE_ROOT / path).resolve()
    contents = resolved.read_text()
    if WORKSPACE_ROOT not in resolved.parents:
        raise ValueError("Path escapes report root")
    return contents
