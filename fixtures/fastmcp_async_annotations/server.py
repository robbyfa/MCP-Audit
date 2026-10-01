from fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("async-annotations")


@mcp.tool()
async def execute_sql(sql: str) -> str:
    """Execute a SQL statement."""
    return sql


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
async def get_db_schema() -> str:
    """Return the PostgreSQL schema."""
    return "public"
