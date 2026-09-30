from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.analysis.scan import scan_path


ROOT = Path(__file__).resolve().parents[1]


def rule_ids(fixture: str) -> set[str]:
    return {finding.rule_id for finding in scan_path(ROOT / "fixtures" / fixture).findings}


@pytest.mark.parametrize(
    ("fixture", "rule_id"),
    [
        ("shell_direct", "MCP001"),
        ("filesystem_unrestricted", "MCP002"),
        ("url_arbitrary", "MCP003"),
        ("url_hostname_unguarded", "MCP003"),
        ("url_guard_after_request", "MCP003"),
        ("destructive_without_approval", "MCP004"),
        ("destructive_without_approval", "MCP010"),
        ("sensitive_to_network", "MCP005"),
    ],
)
def test_positive_rule_cases(fixture: str, rule_id: str) -> None:
    assert rule_id in rule_ids(fixture)


@pytest.mark.parametrize(
    ("fixture", "rule_id"),
    [
        ("shell_safe_allowlist", "MCP001"),
        ("filesystem_restricted", "MCP002"),
        ("filesystem_restricted", "MCP007"),
        ("url_allowlisted", "MCP003"),
        ("url_allowlisted", "MCP007"),
        ("destructive_with_approval", "MCP004"),
        ("destructive_with_approval", "MCP010"),
        ("sensitive_read_only", "MCP005"),
    ],
)
def test_negative_rule_cases(fixture: str, rule_id: str) -> None:
    assert rule_id not in rule_ids(fixture)


def test_hostname_mention_without_rejecting_allowlist_is_not_a_guard() -> None:
    report = scan_path(ROOT / "fixtures/url_hostname_unguarded")
    tool = report.tools[0]
    assert tool.capability.network == "unrestricted_outbound"


def test_allowlist_after_request_does_not_bound_the_sink_input() -> None:
    assert {"MCP003", "MCP007"}.issubset(rule_ids("url_guard_after_request"))


def test_mcp005_reports_classification_destination_and_path() -> None:
    report = scan_path(ROOT / "fixtures/sensitive_to_network")
    finding = next(item for item in report.findings if item.rule_id == "MCP005")
    assert finding.path == ["read_payroll", "agent_context", "post_webhook"]
    assert set(finding.data_classification) == {"financial"}
    assert finding.destination == "unrestricted external URL"
    assert {item.kind for item in finding.evidence} == {"capability_source", "capability_sink"}


def test_mcp005_does_not_link_independent_server_modules() -> None:
    report = scan_path(ROOT / "fixtures")
    cross_server_paths = [
        finding
        for finding in report.findings
        if finding.rule_id == "MCP005" and finding.tool != "read_payroll -> post_webhook"
        and finding.tool != "read_customer_file -> fetch_url"
    ]
    assert cross_server_paths == []


def test_network_finding_contains_precise_code_evidence() -> None:
    report = scan_path(ROOT / "fixtures/url_arbitrary")
    finding = next(item for item in report.findings if item.rule_id == "MCP003")
    evidence = finding.evidence[0]
    assert evidence.location is not None
    assert evidence.location.line == 9
    assert evidence.location.column is not None
    assert evidence.snippet == "requests.get(url, timeout=5)"
    assert finding.impact
    assert finding.recommendation
