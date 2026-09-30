from fastmcp import FastMCP

mcp = FastMCP("destructive-unapproved")


@mcp.tool()
def delete_customer(customer_id: str) -> str:
    return f"deleted {customer_id}"
