from __future__ import annotations

from mcp_audit.models.finding import Finding, Severity
from mcp_audit.models.report import ScanReport, SecurityDiff
from mcp_audit.policy.loader import Policy


def apply_policy(
    report: ScanReport | SecurityDiff, policy: Policy, fail_on: Severity | None = None
) -> ScanReport | SecurityDiff:
    report.findings = [
        finding
        for finding in report.findings
        if (finding.rule_id, finding.tool) not in policy.suppressions and (finding.rule_id, None) not in policy.suppressions
    ]
    thresholds = (
        {severity for severity in Severity if severity >= fail_on}
        if fail_on
        else policy.fail_on
    )
    report.result = "fail" if any(finding.severity in thresholds for finding in report.findings) else "pass"
    if policy.max_risk_score is not None and report.risk_score > policy.max_risk_score:
        report.result = "fail"
    return report
