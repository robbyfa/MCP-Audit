from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from mcp_audit.cli.main import main
from mcp_audit.diff.engine import build_diff
from mcp_audit.diff.models import ChangeClassification, ChangeKind
from mcp_audit.models.capability import Capability, Parameter, Tool
from mcp_audit.models.finding import Evidence, Finding, Location, Severity
from mcp_audit.models.report import ScanReport
from mcp_audit.policy.evaluator import apply_policy
from mcp_audit.policy.loader import Policy, Suppression
from mcp_audit.reporters.markdown import render_diff_markdown
from mcp_audit.reporters.sarif import render_sarif


def _tool(**capabilities: object) -> Tool:
    capability = Capability()
    for field, value in capabilities.items():
        setattr(capability, field, value)
    return Tool(name="example", context="server.py:mcp", source="server.py:5", capability=capability)


def _report(tool: Tool | None = None, finding: Finding | None = None) -> ScanReport:
    return ScanReport(
        target=".",
        server_name="test",
        tools=[tool] if tool else [],
        findings=[finding] if finding else [],
    )


def _capability_diff(before: Tool, after: Tool):
    report = build_diff("baseline", _report(before), _report(after))
    return apply_policy(report, Policy())


@pytest.mark.parametrize(
    ("field", "before", "after"),
    [
        ("filesystem", "allowlisted_files", "unrestricted"),
        ("network", "allowlisted_hosts", "unrestricted_outbound"),
        ("execution", "none", "shell"),
        ("side_effect", "local_write", "external_write"),
    ],
)
def test_ordered_capability_widening_blocks(field: str, before: str, after: str) -> None:
    report = _capability_diff(_tool(**{field: before}), _tool(**{field: after}))
    change = next(change for change in report.changes if change.field == field)
    assert change.kind == ChangeKind.CAPABILITY_WIDENED
    assert change.blocking
    assert report.result == "fail"


@pytest.mark.parametrize(
    ("field", "before", "after"),
    [
        ("filesystem", "unrestricted", "allowlisted_files"),
        ("network", "unrestricted_outbound", "allowlisted_hosts"),
        ("execution", "shell", "none"),
        ("side_effect", "external_write", "local_write"),
    ],
)
def test_ordered_capability_narrowing_is_an_improvement(field: str, before: str, after: str) -> None:
    report = _capability_diff(_tool(**{field: before}), _tool(**{field: after}))
    change = next(change for change in report.changes if change.field == field)
    assert change.kind == ChangeKind.CAPABILITY_NARROWED
    assert change.classification == ChangeClassification.IMPROVEMENT
    assert report.result == "pass"


def test_approval_and_destructive_directionality() -> None:
    regression = _capability_diff(
        _tool(requires_approval=True, destructive=False),
        _tool(requires_approval=False, destructive=True),
    )
    assert {change.kind for change in regression.blocking_regressions} >= {
        ChangeKind.APPROVAL_REMOVED,
        ChangeKind.DESTRUCTIVE_ENABLED,
    }

    improvement = _capability_diff(
        _tool(requires_approval=False, destructive=True),
        _tool(requires_approval=True, destructive=False),
    )
    assert improvement.result == "pass"
    assert {change.kind for change in improvement.improvements} >= {
        ChangeKind.APPROVAL_ADDED,
        ChangeKind.DESTRUCTIVE_DISABLED,
    }


def test_new_safe_tool_warns_but_dangerous_tool_blocks() -> None:
    safe = build_diff("baseline", _report(), _report(_tool()))
    apply_policy(safe, Policy())
    assert safe.result == "pass"
    assert any(change.kind == ChangeKind.TOOL_ADDED for change in safe.warnings)

    dangerous = build_diff("baseline", _report(), _report(_tool(execution="shell")))
    apply_policy(dangerous, Policy())
    assert dangerous.result == "fail"
    assert any(change.field == "execution" for change in dangerous.blocking_regressions)


def test_bounded_input_becoming_unbounded_warns() -> None:
    before = _tool()
    before.parameters = [Parameter("url", bounded=True)]
    after = _tool()
    after.parameters = [Parameter("url", bounded=False)]
    report = _capability_diff(before, after)
    assert report.result == "pass"
    assert any(change.kind == ChangeKind.INPUT_BECAME_UNBOUNDED for change in report.warnings)


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="MCP003",
        title="Network",
        severity=severity,
        tool="example",
        message="Network widened",
        recommendation="Restrict hosts",
        location=Location("server.py", 5),
        evidence=[Evidence("network", kind="network")],
    )


def test_finding_addition_and_severity_changes_follow_thresholds() -> None:
    tool = _tool()
    added_high = build_diff("baseline", _report(tool), _report(tool, _finding(Severity.HIGH)))
    apply_policy(added_high, Policy())
    assert added_high.result == "fail"

    added_medium = build_diff("baseline", _report(tool), _report(tool, _finding(Severity.MEDIUM)))
    apply_policy(added_medium, Policy())
    assert added_medium.result == "pass"
    assert any(change.kind == ChangeKind.FINDING_ADDED for change in added_medium.warnings)

    increased = build_diff(
        "baseline",
        _report(tool, _finding(Severity.MEDIUM)),
        _report(tool, _finding(Severity.HIGH)),
    )
    apply_policy(increased, Policy())
    assert any(change.kind == ChangeKind.FINDING_SEVERITY_INCREASED for change in increased.blocking_regressions)

    decreased = build_diff(
        "baseline",
        _report(tool, _finding(Severity.HIGH)),
        _report(tool, _finding(Severity.MEDIUM)),
    )
    apply_policy(decreased, Policy())
    assert decreased.result == "pass"
    assert any(change.kind == ChangeKind.FINDING_SEVERITY_DECREASED for change in decreased.improvements)


def test_suppressed_new_finding_does_not_block_diff() -> None:
    tool = _tool()
    report = build_diff("baseline", _report(tool), _report(tool, _finding(Severity.HIGH)))
    apply_policy(
        report,
        Policy(suppressions=[Suppression("MCP003", "Reviewed service-mesh control", tool="example")]),
    )
    assert report.result == "pass"
    assert report.new_findings == []
    assert not report.blocking_regressions


def test_tool_identity_includes_registration_context() -> None:
    before = _tool()
    before.context = "one.py:mcp"
    after = _tool()
    after.context = "two.py:mcp"
    report = build_diff("baseline", _report(before), _report(after))
    assert report.new_tools == ["two.py:mcp::example"]
    assert report.removed_tools == ["one.py:mcp::example"]


def test_markdown_and_sarif_share_the_structured_diff() -> None:
    report = build_diff("baseline", _report(_tool()), _report(_tool(network="unrestricted_outbound"), _finding(Severity.HIGH)))
    apply_policy(report, Policy())
    markdown = render_diff_markdown(report)
    assert "❌ Security regression detected" in markdown
    assert "| `example` | network | `none` | `unrestricted_outbound` | BLOCK |" in markdown
    assert "**❌ 2 blocking regressions**" in markdown
    sarif = json.loads(render_sarif(report))
    assert {result["ruleId"] for result in sarif["runs"][0]["results"]} == {"MCP003"}


def test_markdown_distinguishes_warning_only_changes() -> None:
    report = build_diff("baseline", _report(), _report(_tool()))
    apply_policy(report, Policy())

    markdown = render_diff_markdown(report, current_label="PR changes")

    assert "⚠️ No blocking security regression" in markdown
    assert "Current: `PR changes`" in markdown
    assert "| `example` | tool added | `none` | `none` | WARN |" in markdown
    assert "**⚠️ 0 blocking regressions**" in markdown


def test_markdown_renders_improvements_as_a_table() -> None:
    report = build_diff(
        "baseline",
        _report(_tool(filesystem="unrestricted"), _finding(Severity.HIGH)),
        _report(_tool(filesystem="allowlisted_files")),
    )
    apply_policy(report, Policy())

    markdown = render_diff_markdown(report)

    assert "✅ No security regression" in markdown
    assert "### Improvements" in markdown
    assert "| `example` | filesystem | `unrestricted` | `allowlisted_files` | IMPROVED |" in markdown
    assert "| `example` | MCP003 finding removed | `high` | `none` | RESOLVED |" in markdown


BASE_SERVER = """\
import requests
from fastmcp import FastMCP
mcp = FastMCP("diff")

@mcp.tool()
def fetch_status() -> str:
    return requests.get("https://api.example.com/status").text
"""

RISKY_SERVER = BASE_SERVER.replace(
    "def fetch_status() -> str:\n    return requests.get(\"https://api.example.com/status\").text",
    "def fetch_status(url: str) -> str:\n    return requests.get(url).text",
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_two_revision_cli_and_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server = tmp_path / "server.py"
    server.write_text(BASE_SERVER, encoding="utf-8")
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "tests@example.com")
    _git(tmp_path, "config", "user.name", "MCP Audit Tests")
    _git(tmp_path, "add", "server.py")
    _git(tmp_path, "commit", "-m", "baseline")
    server.write_text(RISKY_SERVER, encoding="utf-8")
    _git(tmp_path, "add", "server.py")
    _git(tmp_path, "commit", "-m", "risky")
    output = tmp_path / "diff.json"
    monkeypatch.chdir(tmp_path)

    assert main(["diff", "HEAD~1", "HEAD", "--format", "json", "--output", str(output)]) == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["base"] == "HEAD~1"
    assert payload["current"] == "HEAD"
    assert payload["summary"]["blocking_regressions"] > 0
    assert main(["diff", "missing-ref", "HEAD"]) == 2
