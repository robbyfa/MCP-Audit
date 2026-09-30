from __future__ import annotations

import json
from pathlib import Path

from mcp_audit import RULESET_VERSION, __version__
from mcp_audit.models.report import ScanReport, SecurityDiff


def render_sarif(report: ScanReport | SecurityDiff) -> str:
    rules: dict[str, dict[str, object]] = {}
    results = []
    for finding in report.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.recommendation},
                "properties": {"security-severity": _security_severity(finding.severity.name.lower())},
            },
        )
        result = {
                "ruleId": finding.rule_id,
                "level": _level(finding.severity.name.lower()),
                "message": {"text": _message(finding)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _artifact_uri(finding.location.path)},
                            "region": _region(finding),
                        }
                    }
                ],
            }
        if finding.path:
            result["properties"] = {"capabilityPath": finding.path}
        results.append(result)
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP Audit",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/robbyfa/MCP-Audit",
                        "rules": list(rules.values()),
                        "properties": {"rulesVersion": RULESET_VERSION},
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def _message(finding) -> str:
    parts = [finding.message]
    if finding.impact:
        parts.append(f"Risk: {finding.impact}")
    parts.append(f"Remediation: {finding.recommendation}")
    return "\n\n".join(parts)


def _region(finding) -> dict[str, object]:
    region: dict[str, object] = {"startLine": finding.location.line}
    if finding.location.column is not None:
        region["startColumn"] = finding.location.column
    snippet = next((item.snippet for item in finding.evidence if item.snippet), None)
    if snippet:
        region["snippet"] = {"text": snippet}
    return region


def _artifact_uri(path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.relative_to(Path.cwd()).as_posix()
        except ValueError:
            return candidate.as_uri()
    return candidate.as_posix()


def _level(severity: str) -> str:
    return "error" if severity in {"critical", "high"} else "warning"


def _security_severity(severity: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0"}[severity]
