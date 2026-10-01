from fastmcp import FastMCP

mcp = FastMCP("postgresql-read-only")


@mcp.tool()
def search_species(query: str) -> list[dict]:
    """Search species stored in PostgreSQL."""
    result = database.execute("SELECT * FROM species WHERE name = :query")
    return result.fetchall()


@mcp.tool()
def search_historical_observations(query: str) -> list[dict]:
    """Search historical observations in PostgreSQL."""
    result = database.execute("SELECT * FROM observations WHERE notes = :query")
    return result.fetchall()
