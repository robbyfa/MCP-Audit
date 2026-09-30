from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from mcp_audit.analysis.scan import scan_path
from mcp_audit.models.capability import Tool
from mcp_audit.models.finding import Evidence, Finding, Location, Severity
from mcp_audit.models.report import CapabilityChange, ScanReport, SecurityDiff


def diff_against_base(base: str, target: str | Path = ".") -> SecurityDiff:
    target_path = Path(target).resolve()
    repo_root = _git_root(target_path.parent if target_path.is_file() else target_path)
    relative_target = target_path.relative_to(repo_root)
    head = scan_path(target_path)
    with tempfile.TemporaryDirectory(prefix="mcp-audit-base-") as temp_dir:
        base_root = Path(temp_dir) / "base"
        _export_git_tree(base, base_root, repo_root)
        base_target = base_root / relative_target
        base_report = scan_path(base_target if base_target.exists() else base_root)
    return _build_diff(base, base_report, head)


def _git_root(cwd: Path) -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return Path(result.stdout.strip()).resolve()


def _export_git_tree(base: str, destination: Path, cwd: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "archive", base],
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["tar", "-x", "-C", str(destination)],
        input=archive.stdout,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _build_diff(base_name: str, base: ScanReport, head: ScanReport) -> SecurityDiff:
    base_tools = {tool.name: tool for tool in base.tools}
    head_tools = {tool.name: tool for tool in head.tools}
    new_tools = sorted(head_tools.keys() - base_tools.keys())
    removed_tools = sorted(base_tools.keys() - head_tools.keys())
    changed_tools = sorted(
        name
        for name in head_tools.keys() & base_tools.keys()
        if _tool_signature(head_tools[name]) != _tool_signature(base_tools[name])
    )
    capability_changes = _capability_changes(base_tools, head_tools)

    base_findings = {_finding_key(finding): finding for finding in base.findings}
    head_findings = {_finding_key(finding): finding for finding in head.findings}
    new_findings = [head_findings[key] for key in sorted(head_findings.keys() - base_findings.keys())]
    resolved_findings = [base_findings[key] for key in sorted(base_findings.keys() - head_findings.keys())]
    regressions = _security_regressions(base_tools, head_tools, new_tools, capability_changes)
    actionable = _deduplicate([*new_findings, *regressions])

    return SecurityDiff(
        target=head.target,
        base=base_name,
        server_name=head.server_name,
        risk_before=base.risk_score,
        risk_after=head.risk_score,
        tools=head.tools,
        findings=actionable,
        new_tools=new_tools,
        removed_tools=removed_tools,
        changed_tools=changed_tools,
        capability_changes=capability_changes,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
    )


def _capability_changes(base_tools: dict[str, Tool], head_tools: dict[str, Tool]) -> list[CapabilityChange]:
    changes: list[CapabilityChange] = []
    for name in sorted(base_tools.keys() & head_tools.keys()):
        before = base_tools[name].capability.as_dict()
        after = head_tools[name].capability.as_dict()
        for capability in before.keys() | after.keys():
            if before.get(capability) != after.get(capability):
                changes.append(CapabilityChange(name, capability, before.get(capability), after.get(capability)))
    return changes


def _security_regressions(
    base_tools: dict[str, Tool],
    head_tools: dict[str, Tool],
    new_tools: list[str],
    changes: list[CapabilityChange],
) -> list[Finding]:
    findings: list[Finding] = []
    for name in new_tools:
        tool = head_tools[name]
        if _is_high_impact(tool):
            findings.append(
                Finding(
                    rule_id="MCP016",
                    title="Capability escalation",
                    severity=Severity.HIGH,
                    tool=name,
                    message="A new tool introduces a high-impact security capability.",
                    impact="The MCP server's authority expands beyond the reviewed baseline.",
                    recommendation="Review the capability, require approval where appropriate, and update the approved manifest.",
                    location=_location(tool.source),
                    evidence=[Evidence(message=f"New capabilities: {tool.capability.as_dict()}", kind="capability_diff")],
                )
            )
    changed_names = {change.tool for change in changes}
    for name in sorted(changed_names):
        previous = base_tools[name]
        tool = head_tools[name]
        if previous.capability.requires_approval and not tool.capability.requires_approval:
            findings.append(
                Finding(
                    rule_id="MCP017",
                    title="Approval removed",
                    severity=Severity.HIGH,
                    tool=name,
                    message="A previously approval-gated tool no longer requires approval.",
                    impact="High-impact actions may now execute without human confirmation.",
                    recommendation="Restore the approval boundary or document the reviewed policy exception.",
                    location=_location(tool.source),
                    evidence=[Evidence(message="requires_approval: true -> false", kind="capability_diff")],
                )
            )
        expanded = [change for change in changes if change.tool == name and _is_expansion(change)]
        if expanded:
            findings.append(
                Finding(
                    rule_id="MCP016",
                    title="Capability escalation",
                    severity=Severity.HIGH,
                    tool=name,
                    message="A tool capability expanded relative to the Git baseline.",
                    impact="Existing clients may gain access to broader resources or side effects.",
                    recommendation="Constrain the capability or approve and document the expanded baseline.",
                    location=_location(tool.source),
                    evidence=[
                        Evidence(message=f"{change.capability}: {change.before} -> {change.after}", kind="capability_diff")
                        for change in expanded
                    ],
                )
            )
    return findings


def _tool_signature(tool: Tool) -> tuple[object, ...]:
    return (
        tuple(sorted(tool.capability.as_dict().items(), key=lambda item: item[0])),
        tuple((parameter.name, parameter.annotation, parameter.bounded) for parameter in tool.parameters),
    )


def _finding_key(finding: Finding) -> tuple[str, str]:
    return finding.rule_id, finding.tool or ""


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    result: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        result.setdefault(_finding_key(finding), finding)
    return list(result.values())


def _is_high_impact(tool: Tool) -> bool:
    capability = tool.capability
    return (
        capability.network == "unrestricted_outbound"
        or capability.filesystem == "unrestricted"
        or capability.execution != "none"
        or capability.side_effect in {"external_write", "destructive_action"}
    )


def _is_expansion(change: CapabilityChange) -> bool:
    if change.capability in {"filesystem", "network", "execution", "side_effect"}:
        return _rank(str(change.after)) > _rank(str(change.before))
    if change.capability in {"destructive", "financial"}:
        return change.before is False and change.after is True
    if change.capability == "data_access":
        return bool(set(change.after or []) - set(change.before or []))
    return False


def _rank(value: str) -> int:
    return {
        "none": 0,
        "fixed_file": 1,
        "allowlisted_files": 2,
        "allowlisted_hosts": 2,
        "local_write": 2,
        "directory": 3,
        "external_write": 4,
        "multiple_directories": 4,
        "destructive_action": 5,
        "unrestricted": 5,
        "unrestricted_outbound": 5,
        "shell": 5,
        "arbitrary_code": 6,
    }.get(value, 0)


def _location(source: str) -> Location:
    path, _, line = source.rpartition(":")
    try:
        return Location(path=path or source, line=int(line or "1"))
    except ValueError:
        return Location(path=source)
