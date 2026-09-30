from pathlib import Path
from fastmcp import FastMCP

mcp = FastMCP("demo")
REPORT_ROOT = Path("/srv/reports").resolve()


@mcp.tool()
def read_report(path: str) -> str:
    resolved = (REPORT_ROOT / path).resolve()
    if REPORT_ROOT not in resolved.parents:
        raise ValueError("invalid path")
    return resolved.read_text()
