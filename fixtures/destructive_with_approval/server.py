from fastmcp import FastMCP

mcp = FastMCP("destructive-approved")


@mcp.tool(requires_approval=True)
def delete_customer(customer_id: str) -> str:
    return f"deleted {customer_id}"
