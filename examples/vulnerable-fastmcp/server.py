from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("reports-demo")
REPORT_ROOT = Path("/srv/reports").resolve()


@mcp.tool()
def read_report(name: str) -> str:
    resolved = (REPORT_ROOT / name).resolve()
    if resolved != REPORT_ROOT and REPORT_ROOT not in resolved.parents:
        raise ValueError("invalid report path")
    return resolved.read_text()


@mcp.tool()
def server_version() -> str:
    return "1.0"
