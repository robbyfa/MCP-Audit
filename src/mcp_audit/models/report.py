from __future__ import annotations

from dataclasses import dataclass, field

from mcp_audit import DIFF_SCHEMA_VERSION, REPORT_SCHEMA_VERSION, RULESET_VERSION, __version__
from mcp_audit.diff.models import ChangeClassification, SecurityChange
from mcp_audit.models.capability import Tool
from mcp_audit.models.finding import Finding, Severity


@dataclass(slots=True)
class ScanReport:
    target: str
    server_name: str
    tools: list[Tool] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    result: str = "pass"

    @property
    def risk_score(self) -> int:
        weights = {
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 30,
            Severity.CRITICAL: 45,
        }
        return min(100, sum(weights[finding.severity] for finding in self.findings))

    def counts_by_severity(self) -> dict[str, int]:
        counts = {severity.name.lower(): 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.name.lower()] += 1
        return counts

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "report_type": "scan",
            "versions": {"cli": __version__, "rules": RULESET_VERSION},
            "target": self.target,
            "server": {"name": self.server_name},
            "summary": {
                "tools": len(self.tools),
                "findings": len(self.findings),
                "risk_score": self.risk_score,
                "result": self.result,
                "severity_counts": self.counts_by_severity(),
            },
            "tools": [tool.as_dict() for tool in self.tools],
            "findings": [finding.as_dict() for finding in self.findings],
        }


@dataclass(slots=True)
class CapabilityChange:
    tool: str
    capability: str
    before: object
    after: object

    def as_dict(self) -> dict[str, object]:
        return {
            "tool": self.tool,
            "capability": self.capability,
            "before": self.before,
            "after": self.after,
        }


@dataclass(slots=True)
class SecurityDiff:
    target: str
    base: str
    current: str
    server_name: str
    risk_before: int
    risk_after: int
    tools: list[Tool] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    new_tools: list[str] = field(default_factory=list)
    removed_tools: list[str] = field(default_factory=list)
    changed_tools: list[str] = field(default_factory=list)
    capability_changes: list[CapabilityChange] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    changes: list[SecurityChange] = field(default_factory=list)
    result: str = "pass"

    @property
    def risk_score(self) -> int:
        return self.risk_after

    def counts_by_severity(self) -> dict[str, int]:
        counts = {severity.name.lower(): 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.name.lower()] += 1
        return counts

    @property
    def blocking_regressions(self) -> list[SecurityChange]:
        return [change for change in self.changes if change.blocking]

    @property
    def warnings(self) -> list[SecurityChange]:
        return [change for change in self.changes if change.warning and not change.blocking]

    @property
    def improvements(self) -> list[SecurityChange]:
        return [
            change for change in self.changes if change.classification == ChangeClassification.IMPROVEMENT
        ]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": DIFF_SCHEMA_VERSION,
            "report_type": "diff",
            "versions": {"cli": __version__, "rules": RULESET_VERSION},
            "target": self.target,
            "base": self.base,
            "current": self.current,
            "server": {"name": self.server_name},
            "summary": {
                "risk_before": self.risk_before,
                "risk_after": self.risk_after,
                "result": self.result,
                "new_tools": len(self.new_tools),
                "changed_tools": len(self.changed_tools),
                "new_findings": len(self.new_findings),
                "resolved_findings": len(self.resolved_findings),
                "blocking_regressions": len(self.blocking_regressions),
                "warnings": len(self.warnings),
                "improvements": len(self.improvements),
            },
            "changes": [change.as_dict() for change in self.changes],
            "new_tools": self.new_tools,
            "removed_tools": self.removed_tools,
            "changed_tools": self.changed_tools,
            "capability_changes": [change.as_dict() for change in self.capability_changes],
            "new_findings": [finding.as_dict() for finding in self.new_findings],
            "resolved_findings": [finding.as_dict() for finding in self.resolved_findings],
            "regression_findings": [finding.as_dict() for finding in self.findings],
        }
