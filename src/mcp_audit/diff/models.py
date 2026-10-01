from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mcp_audit.models.finding import Location


class ChangeKind(StrEnum):
    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"
    CAPABILITY_WIDENED = "capability_widened"
    CAPABILITY_NARROWED = "capability_narrowed"
    CAPABILITY_CHANGED = "capability_changed"
    APPROVAL_REMOVED = "approval_removed"
    APPROVAL_ADDED = "approval_added"
    FINDING_ADDED = "finding_added"
    FINDING_REMOVED = "finding_removed"
    FINDING_SEVERITY_INCREASED = "finding_severity_increased"
    FINDING_SEVERITY_DECREASED = "finding_severity_decreased"
    DESTRUCTIVE_ENABLED = "destructive_enabled"
    DESTRUCTIVE_DISABLED = "destructive_disabled"
    INPUT_BECAME_UNBOUNDED = "input_became_unbounded"
    INPUT_BECAME_BOUNDED = "input_became_bounded"


class ChangeClassification(StrEnum):
    REGRESSION = "regression"
    IMPROVEMENT = "improvement"
    NEUTRAL = "neutral"


@dataclass(slots=True)
class SecurityChange:
    tool: str
    context: str
    kind: ChangeKind
    classification: ChangeClassification
    field: str | None = None
    before: object | None = None
    after: object | None = None
    rule_id: str | None = None
    location: Location | None = None
    blocking: bool = False
    warning: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "tool": self.tool,
            "context": self.context,
            "kind": self.kind.value,
            "field": self.field,
            "before": self.before,
            "after": self.after,
            "rule_id": self.rule_id,
            "classification": self.classification.value,
            "blocking": self.blocking,
            "warning": self.warning,
            "location": self.location.as_dict() if self.location else None,
        }
