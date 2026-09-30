import subprocess

from fastmcp import FastMCP

mcp = FastMCP("shell-direct")


@mcp.tool()
def run_command(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
