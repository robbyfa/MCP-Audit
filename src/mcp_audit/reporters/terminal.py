from __future__ import annotations

from mcp_audit.models.finding import Severity
from mcp_audit.models.report import ScanReport, SecurityDiff


def render_terminal(report: ScanReport) -> str:
    counts = report.counts_by_severity()
    lines = [
        "MCP AUDIT",
        f"Server: {report.server_name}",
        f"Target: {report.target}",
        "",
        f"Tools discovered: {len(report.tools)}",
        "",
        "Risk findings",
        f"CRITICAL  {counts['critical']}",
        f"HIGH      {counts['high']}",
        f"MEDIUM    {counts['medium']}",
        f"LOW       {counts['low']}",
        f"Risk score: {report.risk_score}",
        "",
    ]
    for finding in sorted(report.findings, key=lambda item: item.severity, reverse=True):
        lines.extend(_finding_lines(finding))
    lines.append(f"Result: {report.result.upper()}")
    return "\n".join(lines)


def render_diff_terminal(report: SecurityDiff) -> str:
    lines = [
        "MCP SECURITY DIFF",
        f"Base: {report.base}",
        f"Target: {report.target}",
        "",
        "Risk",
        f"{report.risk_before} -> {report.risk_after}",
        "",
        "New tools",
        *([f"+ {name}" for name in report.new_tools] or ["(none)"]),
        "",
        "Removed tools",
        *([f"- {name}" for name in report.removed_tools] or ["(none)"]),
        "",
        "Changed tools",
        *([f"~ {name}" for name in report.changed_tools] or ["(none)"]),
        "",
        "Capability changes",
        *(
            [f"~ {change.tool}.{change.capability}: {change.before} -> {change.after}" for change in report.capability_changes]
            or ["(none)"]
        ),
        "",
        "New findings",
        *(
            [f"+ {finding.rule_id} {finding.severity.name}  {finding.tool or 'n/a'}" for finding in report.new_findings]
            or ["(none)"]
        ),
        "",
        "Resolved findings",
        *(
            [f"- {finding.rule_id} {finding.severity.name}  {finding.tool or 'n/a'}" for finding in report.resolved_findings]
            or ["(none)"]
        ),
        "",
    ]
    regressions = [finding for finding in report.findings if finding.rule_id in {"MCP016", "MCP017"}]
    if regressions:
        lines.append("Regression details")
        for finding in regressions:
            lines.extend(_finding_lines(finding))
    lines.append(f"Result: {report.result.upper()}")
    return "\n".join(lines)


def _finding_lines(finding) -> list[str]:
    path = " -> ".join(finding.path)
    lines = [
        f"{finding.severity.name} {finding.rule_id}",
        f"Tool: {finding.tool or 'n/a'}",
        "",
        finding.title,
        finding.message,
        f"Location: {finding.location.path}:{finding.location.line}",
    ]
    if path:
        lines.append(f"Path: {path}")
    if finding.evidence:
        lines.append("Evidence:")
        for item in finding.evidence[:5]:
            lines.append(f"  - {item.message}")
            if item.snippet:
                lines.append(f"    {item.snippet}")
    if finding.impact:
        lines.extend(["Risk:", finding.impact])
    lines.extend(["Suggested remediation:", finding.recommendation, ""])
    return lines
