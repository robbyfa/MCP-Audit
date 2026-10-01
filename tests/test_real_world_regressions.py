from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.analysis.scan import scan_path


ROOT = Path(__file__).resolve().parents[1]


def test_programmatic_imported_tools_are_discovered() -> None:
    report = scan_path(ROOT / "fixtures/programmatic_registration", require_tools=True)
    assert {tool.name for tool in report.tools} == {"read_write_file", "state"}
    assert {tool.context for tool in report.tools} == {"server.py:mcp"}
    filesystem_tool = next(tool for tool in report.tools if tool.name == "read_write_file")
    assert filesystem_tool.capability.filesystem == "allowlisted_files"


def test_unresolved_programmatic_registration_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text(
        "from fastmcp import FastMCP\nmcp = FastMCP()\nmcp.tool()(missing_tool)\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="cannot resolve registered MCP tool"):
        scan_path(tmp_path, require_tools=True)


def test_path_containment_helper_bounds_filesystem_tools() -> None:
    report = scan_path(ROOT / "fixtures/filesystem_helper_restricted")
    assert {tool.capability.filesystem for tool in report.tools} == {"allowlisted_files"}
    assert not {"MCP002", "MCP007"} & {finding.rule_id for finding in report.findings}


def test_local_writes_are_not_external_sinks() -> None:
    report = scan_path(ROOT / "fixtures/local_filesystem_operations")
    tools = {tool.name: tool for tool in report.tools}
    assert tools["read_file"].capability.side_effect == "none"
    assert tools["write_file"].capability.side_effect == "local_write"
    assert tools["write_file"].capability.data_access == set()
    assert tools["create_folder"].capability.side_effect == "local_write"
    assert tools["send_message"].capability.side_effect == "external_write"
    assert "MCP005" not in {finding.rule_id for finding in report.findings}
    write_evidence = [item.message for item in tools["write_file"].evidence if item.kind == "filesystem"]
    assert write_evidence == ["A filesystem write is reachable from this MCP tool."]


def test_sqlite_reads_are_not_writes_or_exfiltration_sinks() -> None:
    report = scan_path(ROOT / "fixtures/sqlite_read_only")
    assert all(tool.capability.side_effect == "none" for tool in report.tools)
    assert not {"MCP004", "MCP005"} & {finding.rule_id for finding in report.findings}
