from __future__ import annotations

from datetime import date

from mcp_audit.models.finding import Finding, Location, Severity
from mcp_audit.models.report import ScanReport, SecurityDiff
from mcp_audit.diff.models import ChangeClassification, ChangeKind, SecurityChange
from mcp_audit.policy.loader import Policy


def apply_policy(
    report: ScanReport | SecurityDiff, policy: Policy, fail_on: Severity | None = None
) -> ScanReport | SecurityDiff:
    report.findings = [
        finding
        for finding in report.findings
        if not any(
            suppression.matches(finding) and suppression.is_active(date.today())
            for suppression in policy.suppressions
        )
    ]
    thresholds = (
        {severity for severity in Severity if severity >= fail_on}
        if fail_on
        else policy.fail_on
    )
    if isinstance(report, SecurityDiff):
        report.new_findings = [
            finding for finding in report.new_findings if not _suppressed(finding, policy)
        ]
        for change in report.changes:
            change.blocking = _is_blocking_change(change, report, policy, thresholds)
            change.warning = _is_warning_change(change, report, policy, thresholds)
        report.result = "fail" if report.blocking_regressions else "pass"
    else:
        report.result = "fail" if any(finding.severity in thresholds for finding in report.findings) else "pass"
        if policy.max_risk_score is not None and report.risk_score > policy.max_risk_score:
            report.result = "fail"
    return report


def _suppressed(finding: Finding, policy: Policy) -> bool:
    return any(
        suppression.matches(finding) and suppression.is_active(date.today())
        for suppression in policy.suppressions
    )


def _is_blocking_change(
    change: SecurityChange,
    report: SecurityDiff,
    policy: Policy,
    thresholds: set[Severity],
) -> bool:
    if change.classification != ChangeClassification.REGRESSION or _change_is_suppressed(change, policy):
        return False
    if policy.fail_on_changes is not None:
        return _change_event(change, report) in policy.fail_on_changes or change.kind.value in policy.fail_on_changes
    if change.kind in {ChangeKind.APPROVAL_REMOVED, ChangeKind.DESTRUCTIVE_ENABLED}:
        return True
    if change.kind == ChangeKind.CAPABILITY_WIDENED:
        return change.field in {"filesystem", "network", "execution", "side_effect"}
    if change.kind in {ChangeKind.FINDING_ADDED, ChangeKind.FINDING_SEVERITY_INCREASED}:
        finding = _finding_for_change(change, report)
        return finding is not None and finding.severity in thresholds
    return False


def _is_warning_change(
    change: SecurityChange,
    report: SecurityDiff,
    policy: Policy,
    thresholds: set[Severity],
) -> bool:
    if (
        change.blocking
        or change.classification == ChangeClassification.IMPROVEMENT
        or _change_is_suppressed(change, policy)
    ):
        return False
    if policy.warn_on_changes is not None:
        return _change_event(change, report) in policy.warn_on_changes or change.kind.value in policy.warn_on_changes
    if change.kind in {ChangeKind.TOOL_ADDED, ChangeKind.INPUT_BECAME_UNBOUNDED}:
        return True
    if change.kind == ChangeKind.CAPABILITY_WIDENED and change.field in {"sensitivity", "data_access"}:
        return True
    if change.kind in {ChangeKind.FINDING_ADDED, ChangeKind.FINDING_SEVERITY_INCREASED}:
        finding = _finding_for_change(change, report)
        return finding is not None and finding.severity not in thresholds
    return False


def _finding_for_change(change: SecurityChange, report: SecurityDiff) -> Finding | None:
    return next(
        (
            finding
            for finding in report.findings
            if finding.rule_id == change.rule_id and (finding.tool or "") == change.tool
        ),
        None,
    )


def _change_event(change: SecurityChange, report: SecurityDiff) -> str:
    if change.kind == ChangeKind.TOOL_ADDED:
        return "tool_added"
    if change.kind == ChangeKind.APPROVAL_REMOVED:
        return "approval_removed"
    if change.kind == ChangeKind.DESTRUCTIVE_ENABLED:
        return "destructive_capability_added"
    if change.kind == ChangeKind.INPUT_BECAME_UNBOUNDED:
        return "input_became_unbounded"
    if change.kind == ChangeKind.CAPABILITY_WIDENED:
        return {
            "filesystem": "filesystem_widened",
            "network": "network_widened",
            "execution": "shell_execution_added",
            "side_effect": "side_effect_widened",
            "sensitivity": "sensitivity_increased",
        }.get(change.field or "", change.kind.value)
    if change.kind in {ChangeKind.FINDING_ADDED, ChangeKind.FINDING_SEVERITY_INCREASED}:
        finding = _finding_for_change(change, report)
        if finding and finding.rule_id == "MCP005":
            return "sensitive_external_flow_added"
        if finding:
            return f"new_{finding.severity.name.lower()}_finding"
    return change.kind.value


def _change_is_suppressed(change: SecurityChange, policy: Policy) -> bool:
    if not change.rule_id:
        return False
    proxy = Finding(
        rule_id=change.rule_id,
        title="",
        severity=Severity.LOW,
        tool=change.tool or None,
        message="",
        recommendation="",
        location=change.location or Location(path="."),
    )
    return _suppressed(proxy, policy)
