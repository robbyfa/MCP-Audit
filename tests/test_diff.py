from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from mcp_audit.analysis.diff import _build_diff, diff_against_base
from mcp_audit.analysis.scan import scan_path
from mcp_audit.diff.models import ChangeClassification, ChangeKind
from mcp_audit.policy.evaluator import apply_policy
from mcp_audit.policy.loader import Policy
from mcp_audit.reporters.terminal import render_diff_terminal


BASE_SERVER = '''\
import requests
from fastmcp import FastMCP

mcp = FastMCP("diff")

@mcp.tool()
def fetch_status() -> str:
    return requests.get("https://api.example.com/status").text
'''

EXPANDED_SERVER = '''\
import requests
from fastmcp import FastMCP

mcp = FastMCP("diff")

@mcp.tool()
def fetch_status(url: str) -> str:
    return requests.get(url).text
'''

APPROVED_SERVER = '''\
from fastmcp import FastMCP

mcp = FastMCP("diff")

@mcp.tool(requires_approval=True)
def delete_customer(customer_id: str) -> str:
    return customer_id
'''

UNAPPROVED_SERVER = APPROVED_SERVER.replace("@mcp.tool(requires_approval=True)", "@mcp.tool()")

EMPTY_SERVER = "from fastmcp import FastMCP\nmcp = FastMCP('empty')\n"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_security_diff_focuses_on_regressions(tmp_path: Path) -> None:
    server = tmp_path / "server.py"
    server.write_text(BASE_SERVER, encoding="utf-8")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.com")
    _git(tmp_path, "config", "user.name", "MCP Audit Tests")
    _git(tmp_path, "add", "server.py")
    _git(tmp_path, "commit", "-m", "baseline")
    server.write_text(EXPANDED_SERVER, encoding="utf-8")

    report = diff_against_base("HEAD", tmp_path)
    apply_policy(report, Policy())

    assert report.risk_before == 0
    assert report.risk_after > report.risk_before
    assert report.changed_tools == ["fetch_status"]
    assert any(change.capability == "network" for change in report.capability_changes)
    assert {finding.rule_id for finding in report.new_findings} >= {"MCP003", "MCP007"}
    assert any(
        change.kind == ChangeKind.CAPABILITY_WIDENED
        and change.field == "network"
        and change.blocking
        for change in report.changes
    )
    output = render_diff_terminal(report)
    assert "MCP AUDIT - SECURITY DIFF" in output
    assert "Risk: 0 ->" in output
    assert "+ MCP003 fetch_status" in output


def test_diff_json_uses_diff_schema(tmp_path: Path) -> None:
    server = tmp_path / "server.py"
    server.write_text(BASE_SERVER, encoding="utf-8")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.com")
    _git(tmp_path, "config", "user.name", "MCP Audit Tests")
    _git(tmp_path, "add", "server.py")
    _git(tmp_path, "commit", "-m", "baseline")
    server.write_text(EXPANDED_SERVER, encoding="utf-8")

    payload = diff_against_base("HEAD", tmp_path).as_dict()
    assert payload["schema_version"] == "1.0"
    assert payload["report_type"] == "diff"
    assert payload["summary"]["new_findings"] >= 2
    assert payload["current"] == "WORKTREE"
    assert payload["changes"]


def test_diff_detects_removed_approval(tmp_path: Path) -> None:
    server = tmp_path / "server.py"
    server.write_text(APPROVED_SERVER, encoding="utf-8")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.com")
    _git(tmp_path, "config", "user.name", "MCP Audit Tests")
    _git(tmp_path, "add", "server.py")
    _git(tmp_path, "commit", "-m", "approved baseline")
    server.write_text(UNAPPROVED_SERVER, encoding="utf-8")

    report = diff_against_base("HEAD", tmp_path)
    apply_policy(report, Policy())

    assert any(change.kind == ChangeKind.APPROVAL_REMOVED for change in report.blocking_regressions)
    approval_change = next(change for change in report.capability_changes if change.capability == "requires_approval")
    assert approval_change.before is True
    assert approval_change.after is False


def test_diff_does_not_flag_preserved_approval(tmp_path: Path) -> None:
    server = tmp_path / "server.py"
    server.write_text(APPROVED_SERVER, encoding="utf-8")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.com")
    _git(tmp_path, "config", "user.name", "MCP Audit Tests")
    _git(tmp_path, "add", "server.py")
    _git(tmp_path, "commit", "-m", "approved baseline")

    report = diff_against_base("HEAD", tmp_path)

    assert not any(change.kind == ChangeKind.APPROVAL_REMOVED for change in report.changes)
    assert report.changed_tools == []


def test_diff_does_not_flag_approval_added(tmp_path: Path) -> None:
    before = tmp_path / "before.py"
    after = tmp_path / "after.py"
    before.write_text(UNAPPROVED_SERVER, encoding="utf-8")
    after.write_text(APPROVED_SERVER, encoding="utf-8")

    before_report = scan_path(before)
    after_report = scan_path(after)
    before_report.tools[0].context = "server.py:mcp"
    after_report.tools[0].context = "server.py:mcp"
    report = _build_diff("baseline", before_report, after_report)
    apply_policy(report, Policy())
    assert not report.blocking_regressions
    assert any(change.kind == ChangeKind.APPROVAL_ADDED for change in report.improvements)
    assert {finding.rule_id for finding in report.resolved_findings} >= {"MCP004", "MCP010"}


def test_new_high_impact_tool_is_capability_escalation(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    head = tmp_path / "head"
    baseline.mkdir()
    head.mkdir()
    (baseline / "server.py").write_text("from fastmcp import FastMCP\nmcp = FastMCP('empty')\n", encoding="utf-8")
    (head / "server.py").write_text(EXPANDED_SERVER, encoding="utf-8")

    report = _build_diff("baseline", scan_path(baseline), scan_path(head))
    apply_policy(report, Policy())
    assert report.new_tools == ["fetch_status"]
    assert any(change.kind == ChangeKind.TOOL_ADDED for change in report.warnings)
    assert any(change.kind == ChangeKind.CAPABILITY_WIDENED for change in report.blocking_regressions)


def test_diff_allows_intentional_tool_removal(tmp_path: Path) -> None:
    server = tmp_path / "server.py"
    server.write_text(BASE_SERVER, encoding="utf-8")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.com")
    _git(tmp_path, "config", "user.name", "MCP Audit Tests")
    _git(tmp_path, "add", "server.py")
    _git(tmp_path, "commit", "-m", "tool baseline")
    server.write_text(EMPTY_SERVER, encoding="utf-8")

    report = diff_against_base("HEAD", tmp_path)
    apply_policy(report, Policy())
    assert report.removed_tools == ["fetch_status"]
    assert report.risk_after == 0
    assert report.result == "pass"
    assert any(change.classification == ChangeClassification.IMPROVEMENT for change in report.changes)


def test_diff_rejects_zero_tools_in_both_revisions(tmp_path: Path) -> None:
    server = tmp_path / "server.py"
    server.write_text(EMPTY_SERVER, encoding="utf-8")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.com")
    _git(tmp_path, "config", "user.name", "MCP Audit Tests")
    _git(tmp_path, "add", "server.py")
    _git(tmp_path, "commit", "-m", "empty baseline")

    with pytest.raises(ValueError, match="no MCP tools discovered in either"):
        diff_against_base("HEAD", tmp_path)
