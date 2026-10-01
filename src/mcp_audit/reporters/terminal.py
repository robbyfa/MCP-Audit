from __future__ import annotations

from mcp_audit.models.finding import Severity
from mcp_audit.models.report import ScanReport, SecurityDiff
from mcp_audit.diff.models import ChangeClassification, SecurityChange


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
        "MCP AUDIT - SECURITY DIFF",
        f"Baseline: {report.base}",
        f"Current:  {report.current}",
        f"Target: {report.target}",
        "",
        "Tools",
        *([f"+ {name}" for name in report.new_tools] or []),
        *([f"- {name}" for name in report.removed_tools] or []),
        *([f"~ {name}" for name in report.changed_tools] or []),
        *(["(none)"] if not (report.new_tools or report.removed_tools or report.changed_tools) else []),
        "",
        "Blocking regressions",
        *([_change_line(change) for change in report.blocking_regressions] or ["(none)"]),
        "",
        "Warnings",
        *([_change_line(change) for change in report.warnings] or ["(none)"]),
        "",
        "Improvements",
        *([_change_line(change) for change in report.improvements] or ["(none)"]),
        "",
        f"Risk: {report.risk_before} -> {report.risk_after}",
        f"Blocking regressions: {len(report.blocking_regressions)}",
        f"Result: {report.result.upper()}",
    ]
    return "\n".join(lines)


def _change_line(change: SecurityChange) -> str:
    prefix = {
        ChangeClassification.REGRESSION: "+",
        ChangeClassification.IMPROVEMENT: "-",
        ChangeClassification.NEUTRAL: "~",
    }[change.classification]
    subject = f"{change.rule_id} {change.tool}" if change.rule_id else change.tool
    if change.field:
        return f"{prefix} {subject}: {change.field} {_value(change.before)} -> {_value(change.after)}"
    return f"{prefix} {subject}: {change.kind.value}"


def _value(value: object) -> str:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return f"[{', '.join(str(item) for item in value)}]"
    return str(value)


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
