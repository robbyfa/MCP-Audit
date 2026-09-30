from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        normalized = value.strip().upper()
        try:
            return cls[normalized]
        except KeyError as exc:
            valid = ", ".join(severity.name.lower() for severity in cls)
            raise ValueError(f"unknown severity '{value}', expected one of: {valid}") from exc


@dataclass(slots=True)
class Location:
    path: str
    line: int = 1
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"path": self.path, "line": self.line}
        if self.column is not None:
            result["column"] = self.column
        if self.end_line is not None:
            result["end_line"] = self.end_line
        if self.end_column is not None:
            result["end_column"] = self.end_column
        return result


@dataclass(slots=True)
class Evidence:
    message: str
    location: Location | None = None
    snippet: str | None = None
    kind: str = "code"

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "message": self.message,
            "location": self.location.as_dict() if self.location else None,
            "snippet": self.snippet,
        }


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    tool: str | None
    message: str
    recommendation: str
    location: Location
    impact: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    path: list[str] = field(default_factory=list)
    data_classification: list[str] = field(default_factory=list)
    destination: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name.lower(),
            "tool": self.tool,
            "message": self.message,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "location": self.location.as_dict(),
            "evidence": [item.as_dict() for item in self.evidence],
            "path": self.path,
            "data_classification": self.data_classification,
            "destination": self.destination,
        }
