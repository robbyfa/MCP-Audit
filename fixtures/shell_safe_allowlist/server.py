import subprocess

from fastmcp import FastMCP

mcp = FastMCP("shell-allowlist")


@mcp.tool()
def service_status(service: str) -> str:
    if service not in {"api", "worker"}:
        raise ValueError("Unsupported service")
    return subprocess.run(["systemctl", "status", service], capture_output=True, text=True).stdout
