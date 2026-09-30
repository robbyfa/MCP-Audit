from __future__ import annotations

from pathlib import Path

from mcp_audit.models.capability import Tool
from mcp_audit.models.finding import Evidence, Finding, Location, Severity


def evaluate_tools(tools: list[Tool]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        findings.extend(_tool_findings(tool))
    findings.extend(_cross_tool_findings(tools))
    return findings


def _tool_findings(tool: Tool) -> list[Finding]:
    capability = tool.capability
    findings: list[Finding] = []

    if capability.execution in {"shell", "arbitrary_code"}:
        evidence = _evidence(tool, {"execution"})
        findings.append(
            Finding(
                rule_id="MCP001",
                title="Arbitrary shell execution",
                severity=Severity.CRITICAL,
                tool=tool.name,
                message="A tool parameter can reach shell or dynamic code execution.",
                impact="An MCP client could execute commands with the server process's privileges.",
                recommendation="Replace arbitrary command input with an allowlisted operation and avoid shell=True.",
                location=_evidence_location(evidence, tool),
                evidence=evidence,
            )
        )
    if capability.filesystem == "unrestricted":
        evidence = _evidence(tool, {"filesystem"})
        findings.append(
            Finding(
                rule_id="MCP002",
                title="Unrestricted filesystem access",
                severity=Severity.HIGH,
                tool=tool.name,
                message="A tool-controlled path reaches a filesystem operation without an approved-root check.",
                impact="The MCP client may read or overwrite files available to the server process.",
                recommendation="Resolve paths under an allowlisted root and reject paths that escape it.",
                location=_evidence_location(evidence, tool),
                evidence=evidence,
            )
        )
    if capability.network == "unrestricted_outbound":
        evidence = _evidence(tool, {"network"})
        findings.append(
            Finding(
                rule_id="MCP003",
                title="Arbitrary URL or SSRF surface",
                severity=Severity.HIGH,
                tool=tool.name,
                message="A tool-controlled destination reaches an outbound HTTP request without a hostname allowlist.",
                impact="The MCP client may reach arbitrary internet, internal, localhost, or metadata endpoints.",
                recommendation="Parse the URL, require HTTPS, block private ranges, and enforce an explicit hostname allowlist.",
                location=_evidence_location(evidence, tool),
                evidence=evidence,
                destination=capability.network_destination,
            )
        )
    if capability.side_effect in {"external_write", "destructive_action"} and not capability.requires_approval:
        evidence = _evidence(tool, {"network", "approval"}) or tool.evidence
        findings.append(
            Finding(
                rule_id="MCP004",
                title="High-impact side effect without approval",
                severity=Severity.HIGH if capability.side_effect == "destructive_action" else Severity.MEDIUM,
                tool=tool.name,
                message="The tool performs an external or high-impact action without an approval boundary.",
                impact="A model or compromised client could trigger consequential actions without human confirmation.",
                recommendation="Require explicit approval for external writes, destructive actions, and financial actions.",
                location=_evidence_location(evidence, tool),
                evidence=evidence,
            )
        )
    for parameter in tool.parameters:
        if not parameter.bounded and any(token in parameter.name.lower() for token in {"path", "url", "host", "query", "command"}):
            findings.append(
                Finding(
                    rule_id="MCP007",
                    title="Unbounded input",
                    severity=Severity.MEDIUM,
                    tool=tool.name,
                    message=f"Security-sensitive parameter '{parameter.name}' has no detected bounds or allowlist.",
                    impact="Oversized or unconstrained input increases injection, traversal, and resource-exhaustion risk.",
                    recommendation="Add length, scheme, enum, path-root, or hostname allowlist validation.",
                    location=_location(tool),
                    evidence=[Evidence(message=f"Parameter type: {parameter.annotation or 'untyped'}", kind="parameter")],
                )
            )
    if capability.destructive and not capability.requires_approval:
        findings.append(
            Finding(
                rule_id="MCP010",
                title="Destructive tool exposed",
                severity=Severity.HIGH,
                tool=tool.name,
                message="The tool name or description indicates a destructive action without explicit approval.",
                impact="A mistaken or malicious invocation could irreversibly delete or revoke data or access.",
                recommendation="Require human approval and scoped authorization for destructive tools.",
                location=_location(tool),
                evidence=[Evidence(message="Tool semantics indicate a destructive action.", kind="capability")],
            )
        )
    return findings


def _cross_tool_findings(tools: list[Tool]) -> list[Finding]:
    findings: list[Finding] = []
    sensitive_sources = [tool for tool in tools if tool.capability.data_access and tool.capability.sensitivity != "public"]
    external_sinks = [
        tool
        for tool in tools
        if tool.capability.network == "unrestricted_outbound" or tool.capability.side_effect in {"external_write", "public_action"}
    ]
    for source in sensitive_sources:
        for sink in external_sinks:
            if source.name == sink.name or source.context != sink.context:
                continue
            unrestricted = sink.capability.network == "unrestricted_outbound"
            data_classes = sorted(source.capability.data_access)
            sink_evidence = _evidence(sink, {"network"})
            findings.append(
                Finding(
                    rule_id="MCP005",
                    title="Potential data exfiltration path",
                    severity=Severity.CRITICAL if unrestricted else Severity.HIGH,
                    tool=f"{source.name} -> {sink.name}",
                    message=f"{', '.join(data_classes)} data returned by '{source.name}' can enter agent context and reach '{sink.name}'.",
                    impact="Sensitive data exposed to agent context may be sent to an external destination in a later tool call.",
                    recommendation="Constrain the sink destination, require approval, and separate sensitive read tools from external write tools.",
                    location=_evidence_location(sink_evidence, sink),
                    evidence=[
                        Evidence(
                            message=f"Source '{source.name}' returns classified data: {', '.join(data_classes)}.",
                            kind="capability_source",
                            location=_location(source),
                        ),
                        Evidence(
                            message=f"Sink '{sink.name}' permits {sink.capability.network or sink.capability.side_effect}.",
                            kind="capability_sink",
                            location=_evidence_location(sink_evidence, sink),
                            snippet=sink_evidence[0].snippet if sink_evidence else None,
                        ),
                    ],
                    path=[source.name, "agent_context", sink.name],
                    data_classification=data_classes,
                    destination=sink.capability.network_destination or sink.capability.network,
                )
            )
    return findings


def _evidence(tool: Tool, kinds: set[str]) -> list[Evidence]:
    return [item for item in tool.evidence if item.kind in kinds]


def _evidence_location(evidence: list[Evidence], tool: Tool) -> Location:
    return next((item.location for item in evidence if item.location is not None), _location(tool))


def _location(tool: Tool) -> Location:
    source = tool.source
    if ":" not in source:
        return Location(path=source)
    path, line = source.rsplit(":", 1)
    try:
        return Location(path=str(Path(path)), line=int(line))
    except ValueError:
        return Location(path=source)
