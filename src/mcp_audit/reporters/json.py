from __future__ import annotations

import json

from mcp_audit.models.report import ScanReport, SecurityDiff


def render_json(report: ScanReport | SecurityDiff) -> str:
    return json.dumps(report.as_dict(), indent=2, sort_keys=True)
