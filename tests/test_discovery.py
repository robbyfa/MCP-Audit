from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.analysis.scan import scan_path
from mcp_audit.cli.main import main
from mcp_audit.scanners.source import python as python_scanner


ROOT = Path(__file__).resolve().parents[1]


def test_async_fastmcp_tools_with_annotations_are_discovered() -> None:
    fixture = ROOT / "fixtures/fastmcp_async_annotations"
    report = scan_path(fixture, require_tools=True)
    assert {tool.name for tool in report.tools} == {"execute_sql", "get_db_schema"}


def test_single_async_fastmcp_file_is_discovered() -> None:
    fixture = ROOT / "fixtures/fastmcp_async_annotations/server.py"
    report = scan_path(fixture, require_tools=True)
    assert len(report.tools) == 2


def test_missing_target_fails_instead_of_passing(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="scan target does not exist"):
        scan_path(tmp_path / "missing", require_tools=True)


def test_cli_fails_when_no_tools_are_discovered(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    assert main(["scan", str(tmp_path)]) == 2


def test_cli_allow_empty_is_explicit(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--allow-empty"]) == 0


def test_directory_traversal_error_is_not_treated_as_empty(monkeypatch, tmp_path: Path) -> None:
    def inaccessible_walk(root, onerror):
        onerror(PermissionError(1, "Operation not permitted", str(root)))
        return iter(())

    monkeypatch.setattr(python_scanner.os, "walk", inaccessible_walk)
    with pytest.raises(OSError, match="cannot traverse scan target"):
        scan_path(tmp_path)
