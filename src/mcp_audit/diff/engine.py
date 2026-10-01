from __future__ import annotations

import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from mcp_audit.analysis.scan import scan_path
from mcp_audit.diff.models import ChangeClassification, ChangeKind, SecurityChange
from mcp_audit.diff.ordering import compare_capability
from mcp_audit.models.capability import Capability, Tool
from mcp_audit.models.finding import Finding, Location
from mcp_audit.models.report import CapabilityChange, ScanReport, SecurityDiff


ToolIdentity = tuple[str, str]
FindingIdentity = tuple[str, str, str, str]


def diff_against_base(base: str, target: str | Path = ".") -> SecurityDiff:
    target_path = Path(target).resolve()
    repo_root = _git_root(target_path.parent if target_path.is_file() else target_path)
    relative_target = target_path.relative_to(repo_root)
    current = scan_path(target_path)
    baseline = _scan_revision(base, relative_target, repo_root, current.server_name)
    _require_diff_tools(base, baseline, current)
    return build_diff(base, baseline, current, current_name="WORKTREE")


def diff_revisions(base: str, current: str, target: str | Path = ".") -> SecurityDiff:
    target_path = Path(target).resolve()
    repo_root = _git_root(target_path.parent if target_path.is_file() else target_path)
    relative_target = target_path.relative_to(repo_root)
    baseline = _scan_revision(base, relative_target, repo_root, target_path.name)
    current_report = _scan_revision(current, relative_target, repo_root, target_path.name)
    _require_diff_tools(base, baseline, current_report)
    return build_diff(base, baseline, current_report, current_name=current)


def _scan_revision(ref: str, relative_target: Path, repo_root: Path, server_name: str) -> ScanReport:
    with tempfile.TemporaryDirectory(prefix="mcp-audit-revision-") as temp_dir:
        revision_root = Path(temp_dir) / "tree"
        _export_git_tree(ref, revision_root, repo_root)
        revision_target = revision_root / relative_target
        if not revision_target.exists():
            return ScanReport(target=str(revision_target), server_name=server_name)
        return scan_path(revision_target)


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


def _export_git_tree(ref: str, destination: Path, cwd: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    try:
        archive = subprocess.run(
            ["git", "archive", ref],
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
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace").strip() if isinstance(exc.stderr, bytes) else str(exc.stderr).strip()
        raise ValueError(f"cannot read Git revision '{ref}': {detail or 'git archive failed'}") from exc


def _require_diff_tools(base_name: str, baseline: ScanReport, current: ScanReport) -> None:
    if not baseline.tools and not current.tools:
        raise ValueError(
            f"no MCP tools discovered in either {current.target} or baseline {base_name}; "
            "check the target path, filesystem access, and supported decorators"
        )


def build_diff(
    base_name: str,
    baseline: ScanReport,
    current: ScanReport,
    *,
    current_name: str = "HEAD",
) -> SecurityDiff:
    baseline_tools = {_tool_identity(tool): tool for tool in baseline.tools}
    current_tools = {_tool_identity(tool): tool for tool in current.tools}
    display_names = _display_names([*baseline_tools, *current_tools])
    added_ids = sorted(current_tools.keys() - baseline_tools.keys())
    removed_ids = sorted(baseline_tools.keys() - current_tools.keys())
    common_ids = sorted(current_tools.keys() & baseline_tools.keys())

    changes: list[SecurityChange] = []
    for identity in added_ids:
        tool = current_tools[identity]
        changes.append(_tool_change(tool, ChangeKind.TOOL_ADDED, ChangeClassification.NEUTRAL))
        changes.extend(_new_tool_capability_changes(tool))
    for identity in removed_ids:
        changes.append(_tool_change(baseline_tools[identity], ChangeKind.TOOL_REMOVED, ChangeClassification.IMPROVEMENT))
    for identity in common_ids:
        changes.extend(_tool_capability_changes(baseline_tools[identity], current_tools[identity]))
        changes.extend(_parameter_changes(baseline_tools[identity], current_tools[identity]))

    baseline_findings = {_finding_identity(finding, baseline_tools): finding for finding in baseline.findings}
    current_findings = {_finding_identity(finding, current_tools): finding for finding in current.findings}
    added_finding_ids = sorted(current_findings.keys() - baseline_findings.keys())
    removed_finding_ids = sorted(baseline_findings.keys() - current_findings.keys())
    common_finding_ids = sorted(current_findings.keys() & baseline_findings.keys())
    new_findings = [current_findings[key] for key in added_finding_ids]
    resolved_findings = [baseline_findings[key] for key in removed_finding_ids]
    changes.extend(
        _finding_change(
            current_findings[identity],
            identity[1],
            ChangeKind.FINDING_ADDED,
            ChangeClassification.REGRESSION,
        )
        for identity in added_finding_ids
    )
    changes.extend(
        _finding_change(
            baseline_findings[identity],
            identity[1],
            ChangeKind.FINDING_REMOVED,
            ChangeClassification.IMPROVEMENT,
        )
        for identity in removed_finding_ids
    )

    severity_changed_findings: list[Finding] = []
    for identity in common_finding_ids:
        before = baseline_findings[identity]
        after = current_findings[identity]
        if before.severity == after.severity:
            continue
        increased = after.severity > before.severity
        changes.append(
            SecurityChange(
                tool=after.tool or "",
                context=identity[1],
                kind=ChangeKind.FINDING_SEVERITY_INCREASED if increased else ChangeKind.FINDING_SEVERITY_DECREASED,
                field="severity",
                before=before.severity.name.lower(),
                after=after.severity.name.lower(),
                rule_id=after.rule_id,
                classification=ChangeClassification.REGRESSION if increased else ChangeClassification.IMPROVEMENT,
                location=after.location,
            )
        )
        if increased:
            severity_changed_findings.append(after)

    capability_changes = [
        CapabilityChange(change.tool, change.field or "", change.before, change.after)
        for change in changes
        if change.kind in {
            ChangeKind.CAPABILITY_WIDENED,
            ChangeKind.CAPABILITY_NARROWED,
            ChangeKind.CAPABILITY_CHANGED,
            ChangeKind.APPROVAL_REMOVED,
            ChangeKind.APPROVAL_ADDED,
            ChangeKind.DESTRUCTIVE_ENABLED,
            ChangeKind.DESTRUCTIVE_DISABLED,
        }
    ]
    changed_ids = [
        identity
        for identity in common_ids
        if any(change.context == identity[0] and change.tool == identity[1] for change in changes)
    ]
    return SecurityDiff(
        target=current.target,
        base=base_name,
        current=current_name,
        server_name=current.server_name,
        risk_before=baseline.risk_score,
        risk_after=current.risk_score,
        tools=current.tools,
        findings=[*new_findings, *severity_changed_findings],
        new_tools=[display_names[identity] for identity in added_ids],
        removed_tools=[display_names[identity] for identity in removed_ids],
        changed_tools=[display_names[identity] for identity in changed_ids],
        capability_changes=capability_changes,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        changes=changes,
    )


def _tool_identity(tool: Tool) -> ToolIdentity:
    return tool.context, tool.name


def _display_names(identities: list[ToolIdentity]) -> dict[ToolIdentity, str]:
    unique_identities = set(identities)
    counts = Counter(name for _, name in unique_identities)
    return {
        identity: identity[1] if counts[identity[1]] == 1 else f"{identity[0]}::{identity[1]}"
        for identity in unique_identities
    }


def _tool_change(tool: Tool, kind: ChangeKind, classification: ChangeClassification) -> SecurityChange:
    return SecurityChange(
        tool=tool.name,
        context=tool.context,
        kind=kind,
        classification=classification,
        location=_location(tool.source),
    )


def _new_tool_capability_changes(tool: Tool) -> list[SecurityChange]:
    return _capability_field_changes(tool, Capability().as_dict(), tool.capability.as_dict())


def _tool_capability_changes(before: Tool, after: Tool) -> list[SecurityChange]:
    return _capability_field_changes(after, before.capability.as_dict(), after.capability.as_dict())


def _capability_field_changes(tool: Tool, before: dict[str, object], after: dict[str, object]) -> list[SecurityChange]:
    changes: list[SecurityChange] = []
    for field in sorted(before.keys() | after.keys()):
        old = before.get(field)
        new = after.get(field)
        if old == new:
            continue
        if field == "requires_approval":
            kind = ChangeKind.APPROVAL_REMOVED if old is True and new is False else ChangeKind.APPROVAL_ADDED
            classification = ChangeClassification.REGRESSION if kind == ChangeKind.APPROVAL_REMOVED else ChangeClassification.IMPROVEMENT
        elif field == "destructive":
            kind = ChangeKind.DESTRUCTIVE_ENABLED if new is True else ChangeKind.DESTRUCTIVE_DISABLED
            classification = ChangeClassification.REGRESSION if new is True else ChangeClassification.IMPROVEMENT
        else:
            direction = compare_capability(field, old, new)
            if direction == 1:
                kind = ChangeKind.CAPABILITY_WIDENED
                classification = ChangeClassification.REGRESSION
            elif direction == -1:
                kind = ChangeKind.CAPABILITY_NARROWED
                classification = ChangeClassification.IMPROVEMENT
            else:
                kind = ChangeKind.CAPABILITY_CHANGED
                classification = ChangeClassification.NEUTRAL
        changes.append(
            SecurityChange(
                tool=tool.name,
                context=tool.context,
                kind=kind,
                field=field,
                before=old,
                after=new,
                classification=classification,
                location=_location(tool.source),
            )
        )
    return changes


def _parameter_changes(before: Tool, after: Tool) -> list[SecurityChange]:
    changes: list[SecurityChange] = []
    before_parameters = {parameter.name: parameter for parameter in before.parameters}
    after_parameters = {parameter.name: parameter for parameter in after.parameters}
    for name in sorted(before_parameters.keys() & after_parameters.keys()):
        old = before_parameters[name].bounded
        new = after_parameters[name].bounded
        if old == new:
            continue
        became_unbounded = old and not new
        changes.append(
            SecurityChange(
                tool=after.name,
                context=after.context,
                kind=ChangeKind.INPUT_BECAME_UNBOUNDED if became_unbounded else ChangeKind.INPUT_BECAME_BOUNDED,
                field=f"parameter.{name}.bounded",
                before=old,
                after=new,
                classification=ChangeClassification.REGRESSION if became_unbounded else ChangeClassification.IMPROVEMENT,
                location=_location(after.source),
            )
        )
    return changes


def _finding_identity(finding: Finding, tools: dict[ToolIdentity, Tool]) -> FindingIdentity:
    tool_name = finding.tool or ""
    related_names = {tool_name, *finding.path}
    contexts = sorted({context for context, name in tools if name in related_names})
    context = contexts[0] if len(contexts) == 1 else ""
    evidence_kind = next((item.kind for item in finding.evidence if item.kind), "finding")
    return finding.rule_id, context, tool_name, evidence_kind


def _finding_change(
    finding: Finding,
    context: str,
    kind: ChangeKind,
    classification: ChangeClassification,
) -> SecurityChange:
    return SecurityChange(
        tool=finding.tool or "",
        context=context,
        kind=kind,
        field="finding",
        before=None if kind == ChangeKind.FINDING_ADDED else finding.severity.name.lower(),
        after=finding.severity.name.lower() if kind == ChangeKind.FINDING_ADDED else None,
        rule_id=finding.rule_id,
        classification=classification,
        location=finding.location,
    )


def _location(source: str) -> Location:
    path, _, line = source.rpartition(":")
    try:
        return Location(path=path or source, line=int(line or "1"))
    except ValueError:
        return Location(path=source)
