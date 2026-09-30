from fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def delete_customer(customer_id: str) -> str:
    return customer_id
