from fastmcp import FastMCP


mcp = FastMCP("sqlite-read-only")


@mcp.tool()
def read_query(query: str) -> list[dict]:
    """Execute a read-only query on the Messages database."""
    cursor.execute(query)
    return cursor.fetchall()


@mcp.tool()
def list_tables() -> list[str]:
    """List tables from the Messages database."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return [row[0] for row in cursor.fetchall()]
