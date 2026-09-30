from __future__ import annotations

from mcp_audit.models.finding import Evidence, Finding, Location, Severity
from mcp_audit.models.report import ScanReport
from mcp_audit.policy.evaluator import apply_policy
from mcp_audit.policy.loader import Policy, _parse_small_yaml_subset


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
