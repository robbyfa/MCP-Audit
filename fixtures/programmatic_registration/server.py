from fastmcp import FastMCP

from fixture_tools.filesystem import read_write_file
from fixture_tools.state import get_state


mcp = FastMCP("programmatic-registration")

mcp.tool()(read_write_file)
mcp.tool(name="state")(get_state)
