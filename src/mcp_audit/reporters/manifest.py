from __future__ import annotations

from mcp_audit.models.report import ScanReport


def render_manifest(report: ScanReport) -> str:
    lines = [
        'schema_version: "1.0"',
        "server:",
        f"  name: {report.server_name}",
        "tools:",
    ]
    for tool in report.tools:
        capability = tool.capability
        lines.extend(
            [
                f"  {tool.name}:",
                f"    source: {tool.source}",
                f"    data_access: [{', '.join(sorted(capability.data_access))}]",
                f"    side_effect: {capability.side_effect}",
                f"    filesystem: {capability.filesystem}",
                f"    network: {capability.network}",
                f"    network_destination: {capability.network_destination or 'none'}",
                f"    execution: {capability.execution}",
                f"    requires_approval: {str(capability.requires_approval).lower()}",
            ]
        )
    return "\n".join(lines) + "\n"
