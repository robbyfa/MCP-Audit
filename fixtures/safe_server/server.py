from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("reports")

REPORT_ROOT = Path("/workspace/reports").resolve()


@mcp.tool()
def read_report(filename: str) -> str:
    """Read an approved customer report from the report workspace."""
    path = (REPORT_ROOT / filename).resolve()
    if REPORT_ROOT not in path.parents:
        raise ValueError("Invalid path")
    return path.read_text()
