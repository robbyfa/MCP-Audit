import os

from fastmcp import FastMCP


mcp = FastMCP("local-filesystem-operations")


@mcp.tool()
def read_file(file: str) -> str:
    with open(file, "r") as handle:
        return handle.read()


@mcp.tool()
def write_file(file: str, content: str) -> str:
    with open(file, "w") as handle:
        handle.write(content)
    return file


@mcp.tool()
def create_folder(folder: str) -> str:
    os.makedirs(folder)
    return folder


@mcp.tool()
def send_message(message: str) -> str:
    """Prepare a message locally without any network destination."""
    return message
