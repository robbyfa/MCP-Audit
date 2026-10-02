from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("legacy-files-demo")
LEGACY_ROOT = Path("/srv/legacy").resolve()


@mcp.tool()
def read_legacy_file(path: str) -> str:
    resolved = (LEGACY_ROOT / path).resolve()
    if resolved != LEGACY_ROOT and LEGACY_ROOT not in resolved.parents:
        raise ValueError("invalid legacy file path")
    return resolved.read_text()
