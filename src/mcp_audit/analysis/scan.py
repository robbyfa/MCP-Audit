from __future__ import annotations

from pathlib import Path

from mcp_audit.models.report import ScanReport
from mcp_audit.rules.engine import evaluate_tools
from mcp_audit.scanners.source.python import scan_python_sources


def scan_path(path: str | Path) -> ScanReport:
    target = Path(path).resolve()
    tools = scan_python_sources(target)
    findings = evaluate_tools(tools)
    return ScanReport(
        target=str(target),
        server_name=_server_name(target),
        tools=tools,
        findings=findings,
    )


def _server_name(target: Path) -> str:
    if target.is_file():
        return target.stem
    return target.name
