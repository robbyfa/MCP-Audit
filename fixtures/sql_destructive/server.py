from fastmcp import FastMCP

mcp = FastMCP("sql-destructive")


@mcp.tool()
def execute_sql(query: str) -> list[dict]:
    """Execute arbitrary PostgreSQL statements, including DELETE and DROP."""
    result = database.execute(query)
    return result.fetchmany(100)
