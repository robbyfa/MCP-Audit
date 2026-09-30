from __future__ import annotations

from dataclasses import dataclass, field

from mcp_audit.models.finding import Evidence


@dataclass(slots=True)
class Capability:
    data_access: set[str] = field(default_factory=set)
    side_effect: str = "none"
    filesystem: str = "none"
    network: str = "none"
    network_destination: str | None = None
    execution: str = "none"
    sensitivity: str = "public"
    destructive: bool = False
    financial: bool = False
    requires_approval: bool = False
    audit_metadata: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "data_access": sorted(self.data_access),
            "side_effect": self.side_effect,
            "filesystem": self.filesystem,
            "network": self.network,
            "network_destination": self.network_destination,
            "execution": self.execution,
            "sensitivity": self.sensitivity,
            "destructive": self.destructive,
            "financial": self.financial,
            "requires_approval": self.requires_approval,
            "audit_metadata": self.audit_metadata,
        }


@dataclass(slots=True)
class Parameter:
    name: str
    annotation: str | None = None
    default: str | None = None
    bounded: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "annotation": self.annotation,
            "default": self.default,
            "bounded": self.bounded,
        }


@dataclass(slots=True)
class Tool:
    name: str
    source: str
    context: str = ""
    description: str = ""
    parameters: list[Parameter] = field(default_factory=list)
    capability: Capability = field(default_factory=Capability)
    evidence: list[Evidence] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "source": self.source,
            "context": self.context,
            "description": self.description,
            "parameters": [parameter.as_dict() for parameter in self.parameters],
            "capabilities": self.capability.as_dict(),
            "evidence": [item.as_dict() for item in self.evidence],
        }
