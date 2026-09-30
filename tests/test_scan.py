from __future__ import annotations

from pathlib import Path

from mcp_audit.analysis.scan import scan_path
from mcp_audit.policy.evaluator import apply_policy
from mcp_audit.policy.loader import Policy


ROOT = Path(__file__).resolve().parents[1]


def test_safe_server_has_no_high_risk_findings() -> None:
    report = apply_policy(scan_path(ROOT / "fixtures/safe_server"), Policy())
    rule_ids = {finding.rule_id for finding in report.findings}
    assert "MCP001" not in rule_ids
    assert "MCP003" not in rule_ids
    assert "MCP005" not in rule_ids


def test_vulnerable_server_detects_core_v0_1_rules() -> None:
    report = apply_policy(scan_path(ROOT / "fixtures/vulnerable_server"), Policy())
    rule_ids = {finding.rule_id for finding in report.findings}
    assert {"MCP001", "MCP002", "MCP003", "MCP005", "MCP010"}.issubset(rule_ids)
    assert report.result == "fail"


def test_json_shape_is_machine_readable() -> None:
    report = scan_path(ROOT / "fixtures/vulnerable_server")
    payload = report.as_dict()
    assert payload["summary"]["tools"] == 4
    assert payload["findings"]
