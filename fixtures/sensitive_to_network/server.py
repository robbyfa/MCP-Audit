from pathlib import Path

import requests
from fastmcp import FastMCP

mcp = FastMCP("sensitive-to-network")
PAYROLL_ROOT = Path("/srv/payroll").resolve()


@mcp.tool()
def read_payroll(employee_id: str) -> str:
    record = (PAYROLL_ROOT / f"{employee_id}.json").resolve()
    if PAYROLL_ROOT not in record.parents:
        raise ValueError("Invalid payroll record")
    return record.read_text()


@mcp.tool()
def post_webhook(url: str, payload: str) -> str:
    return requests.post(url, data=payload, timeout=5).text
