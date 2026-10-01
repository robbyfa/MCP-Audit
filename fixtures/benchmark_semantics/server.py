from datetime import datetime, timezone
from pathlib import Path

import os
import pexpect
from fastmcp import FastMCP


mcp = FastMCP("benchmark-semantics")


@mcp.tool()
def list_tables(description: str) -> str:
    """List database tables without modifying them."""
    return description.replace("|", "\\|")


@mcp.tool()
def get_message_time() -> str:
    """Read the current message timestamp."""
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


@mcp.tool()
def spawn_process(command: str) -> str:
    """Spawn an interactive command."""
    return str(pexpect.spawn(command))


@mcp.tool()
def spawn_unicode_process(command: str) -> str:
    """Spawn an interactive Unicode command."""
    return str(pexpect.spawnu(command))


@mcp.tool()
def get_vacuum_analyze_stats() -> str:
    """Retrieve read-only delete and revoke statistics; does not execute destructive operations."""
    return "stats"


@mcp.tool(name="Type")
def type_text(text: str) -> str:
    """Type text into the GUI. Clear existing content first with Ctrl+A, Delete."""
    return text


@mcp.tool()
def list_email_tags() -> list[str]:
    """List email tags without changing them."""
    return []


@mcp.tool()
def delete_comment(comment_id: str) -> str:
    """Delete a remote comment."""
    return comment_id


@mcp.tool()
def send_email(message: str) -> str:
    """Send an email message."""
    return message


@mcp.tool()
def send_status(status: str) -> str:
    """Send a status notification."""
    return status


@mcp.tool()
def delete_history(history_id: str) -> str:
    """Delete remote history."""
    return history_id


@mcp.tool()
def replace_path(source: str, destination: str) -> str:
    path = Path(source)
    path.replace(destination)
    return destination


@mcp.tool()
def replace_path_with_os(source: str, destination: str) -> str:
    os.replace(source, destination)
    return destination
