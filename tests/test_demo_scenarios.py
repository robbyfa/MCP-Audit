from __future__ import annotations

from pathlib import Path

from mcp_audit.analysis.diff import _build_diff
from mcp_audit.analysis.scan import scan_path
from mcp_audit.diff.models import ChangeKind
from mcp_audit.policy.evaluator import apply_policy
from mcp_audit.policy.loader import Policy


SCENARIOS = Path(__file__).resolve().parents[1] / "examples/vulnerable-fastmcp/scenarios"


def _rules(path: Path) -> set[str]:
    return {finding.rule_id for finding in scan_path(path).findings}


def test_unrestricted_fetch_demo() -> None:
    scenario = SCENARIOS / "unrestricted_fetch"
    assert "MCP003" not in _rules(scenario / "before.py")
    assert {"MCP003", "MCP007"}.issubset(_rules(scenario / "after.py"))


def test_filesystem_expansion_demo() -> None:
    scenario = SCENARIOS / "filesystem_expansion"
    assert "MCP002" not in _rules(scenario / "before.py")
    assert {"MCP002", "MCP007"}.issubset(_rules(scenario / "after.py"))


def test_approval_removed_demo() -> None:
    scenario = SCENARIOS / "approval_removed"
    before = scan_path(scenario / "before.py")
    after = scan_path(scenario / "after.py")
    before.tools[0].context = "server.py:mcp"
    after.tools[0].context = "server.py:mcp"
    report = _build_diff(
        "baseline",
        before,
        after,
    )
    apply_policy(report, Policy())
    assert any(change.kind == ChangeKind.APPROVAL_REMOVED for change in report.blocking_regressions)


def test_allowlist_added_resolves_network_findings() -> None:
    scenario = SCENARIOS / "network_allowlist_added"
    report = _build_diff(
        "baseline",
        scan_path(scenario / "before.py"),
        scan_path(scenario / "after.py"),
    )
    assert {finding.rule_id for finding in report.resolved_findings} >= {"MCP003", "MCP007"}
    assert not report.new_findings
