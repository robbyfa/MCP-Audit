from __future__ import annotations

import json
from pathlib import Path

from mcp_audit.analysis.scan import scan_path
from mcp_audit.reporters.sarif import render_sarif
from mcp_audit.reporters.terminal import render_terminal


ROOT = Path(__file__).resolve().parents[1]


def test_json_schema_has_stable_version_and_structured_evidence() -> None:
    payload = scan_path(ROOT / "fixtures/url_arbitrary").as_dict()
    assert payload["schema_version"] == "1.0"
    assert payload["report_type"] == "scan"
    assert payload["versions"] == {"cli": "0.2.1", "rules": "0.2"}
    evidence = payload["findings"][0]["evidence"][0]
    assert set(evidence) == {"kind", "message", "location", "snippet"}
    assert payload["tools"][0]["context"] == "server.py:mcp"


def test_terminal_finding_answers_risk_and_remediation() -> None:
    output = render_terminal(scan_path(ROOT / "fixtures/url_arbitrary"))
    assert "Risk:" in output
    assert "Suggested remediation:" in output
    assert "requests.get(url, timeout=5)" in output


def test_sarif_contains_source_region_snippet_and_help() -> None:
    payload = json.loads(render_sarif(scan_path(ROOT / "fixtures/url_arbitrary")))
    run = payload["runs"][0]
    assert run["tool"]["driver"]["semanticVersion"] == "0.2.1"
    assert run["tool"]["driver"]["properties"]["rulesVersion"] == "0.2"
    result = next(item for item in run["results"] if item["ruleId"] == "MCP003")
    region = result["locations"][0]["physicalLocation"]["region"]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "fixtures/url_arbitrary/server.py"
    assert region["startLine"] == 9
    assert region["startColumn"] > 0
    assert region["snippet"]["text"] == "requests.get(url, timeout=5)"
    rule = next(item for item in run["tool"]["driver"]["rules"] if item["id"] == "MCP003")
    assert rule["help"]["text"]
