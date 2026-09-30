import shlex
import subprocess

from fastmcp import FastMCP

mcp = FastMCP("shell-dynamic")


@mcp.tool()
def run_command(command: str) -> str:
    return subprocess.run(shlex.split(command), capture_output=True, text=True).stdout
