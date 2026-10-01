from __future__ import annotations

from datetime import date, timedelta

import pytest

from mcp_audit.cli.main import main
from mcp_audit.models.finding import Evidence, Finding, Location, Severity
from mcp_audit.models.report import ScanReport
from mcp_audit.diff.engine import build_diff
from mcp_audit.diff.models import ChangeKind
from mcp_audit.models.capability import Capability, Tool
from mcp_audit.policy.evaluator import apply_policy
from mcp_audit.policy.loader import Policy, Suppression, _parse_small_yaml_subset


def _report(severity: Severity) -> ScanReport:
    return ScanReport(
        target=".",
        server_name="test",
        findings=[
            Finding(
                rule_id="MCP001",
                title="test",
                severity=severity,
                tool="test",
                message="test",
                impact="test",
                recommendation="test",
                location=Location("server.py"),
                evidence=[Evidence("test")],
            )
        ],
    )


def test_fail_on_is_a_minimum_severity() -> None:
    report = apply_policy(_report(Severity.CRITICAL), Policy(), Severity.HIGH)
    assert report.result == "fail"


def test_custom_fail_on_replaces_defaults() -> None:
    policy = _parse_small_yaml_subset("policy:\n  fail_on:\n    - critical\n")
    assert policy.fail_on == {Severity.CRITICAL}
    assert apply_policy(_report(Severity.HIGH), policy).result == "pass"


def test_active_suppression_requires_reason_and_hides_matching_finding() -> None:
    policy = _parse_small_yaml_subset(
        """
suppress:
  - rule: MCP001
    tool: test
    reason: Reviewed test fixture
    expires: 2999-01-01
"""
    )
    report = apply_policy(_report(Severity.CRITICAL), policy)
    assert report.findings == []
    assert report.result == "pass"


def test_expired_suppression_does_not_hide_finding() -> None:
    policy = Policy(
        suppressions=[
            Suppression(
                rule_id="MCP001",
                tool="test",
                reason="Temporary exception",
                expires=date.today() - timedelta(days=1),
            )
        ]
    )
    report = apply_policy(_report(Severity.CRITICAL), policy)
    assert report.findings
    assert report.result == "fail"


def test_suppression_without_reason_is_rejected() -> None:
    with pytest.raises(ValueError, match="requires a non-empty reason"):
        _parse_small_yaml_subset("suppress:\n  - rule: MCP003\n    tool: fetch_url\n")


def test_unknown_suppression_rule_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown suppression rule"):
        _parse_small_yaml_subset("suppress:\n  - rule: MCP999\n    reason: typo\n")


def test_policy_check_fails_for_expired_suppression(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "suppress:\n  - rule: MCP003\n    reason: old exception\n    expires: 2000-01-01\n",
        encoding="utf-8",
    )
    assert main(["policy", "check", str(policy_path)]) == 1


def test_semantic_change_policy_can_warn_instead_of_block() -> None:
    before = Tool("fetch", "server.py:1", "server.py:mcp", capability=Capability(network="none"))
    after = Tool(
        "fetch",
        "server.py:1",
        "server.py:mcp",
        capability=Capability(network="unrestricted_outbound"),
    )
    report = build_diff(
        "baseline",
        ScanReport("before", "server", tools=[before]),
        ScanReport("after", "server", tools=[after]),
    )
    policy = _parse_small_yaml_subset(
        "policy:\n  ci:\n    fail_on_changes: [approval_removed]\n    warn_on_changes: [network_widened]\n"
    )
    apply_policy(report, policy)
    assert report.result == "pass"
    assert any(change.kind == ChangeKind.CAPABILITY_WIDENED for change in report.warnings)


def test_unknown_semantic_change_event_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown change event"):
        _parse_small_yaml_subset("policy:\n  ci:\n    fail_on_changes: [made_up_event]\n")
