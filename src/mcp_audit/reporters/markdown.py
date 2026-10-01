from __future__ import annotations

from mcp_audit.diff.models import SecurityChange
from mcp_audit.models.report import SecurityDiff


def render_diff_markdown(report: SecurityDiff) -> str:
    result = "Security regression detected" if report.blocking_regressions else "No security regression"
    lines = [
        "## MCP Audit",
        "",
        f"**{result}**",
        "",
        f"Baseline: `{report.base}`  ",
        f"Current: `{report.current}`",
        "",
    ]
    notable = [*report.blocking_regressions, *report.warnings]
    if notable:
        lines.extend(
            [
                "| Tool | Change | Before | After | Policy |",
                "|---|---|---|---|---|",
                *[_change_row(change) for change in notable],
                "",
            ]
        )
    if report.new_findings:
        lines.extend(["### New findings", ""])
        lines.extend(
            f"- **{finding.severity.name}** `{finding.rule_id}` - {finding.tool or 'n/a'}"
            for finding in report.new_findings
        )
        lines.append("")
    if report.improvements:
        lines.extend(["### Improvements", ""])
        lines.extend(f"- {_change_description(change)}" for change in report.improvements)
        lines.append("")
    lines.append(f"**{len(report.blocking_regressions)} blocking regressions**")
    return "\n".join(lines) + "\n"


def _change_row(change: SecurityChange) -> str:
    policy = "BLOCK" if change.blocking else "WARN"
    return (
        f"| `{_escape(change.tool)}` | {_escape(_change_label(change))} | "
        f"`{_escape(_value(change.before))}` | `{_escape(_value(change.after))}` | {policy} |"
    )


def _change_description(change: SecurityChange) -> str:
    return (
        f"`{change.tool}`: {_change_label(change)} "
        f"`{_value(change.before)}` -> `{_value(change.after)}`"
    )


def _change_label(change: SecurityChange) -> str:
    if change.rule_id:
        return f"{change.rule_id} {change.kind.value.replace('_', ' ')}"
    return (change.field or change.kind.value).replace("_", " ")


def _value(value: object) -> str:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "none"
    return str(value)


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
