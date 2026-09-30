from pathlib import Path

from fastmcp import FastMCP

mcp = FastMCP("sensitive-read-only")
CUSTOMER_ROOT = Path("/srv/customers").resolve()


@mcp.tool()
def read_customer_record(customer_id: str) -> str:
    record = (CUSTOMER_ROOT / f"{customer_id}.json").resolve()
    if CUSTOMER_ROOT not in record.parents:
        raise ValueError("Invalid customer record")
    return record.read_text()
