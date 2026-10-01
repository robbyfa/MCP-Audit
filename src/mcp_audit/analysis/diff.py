"""Compatibility imports for the semantic diff engine."""

from mcp_audit.diff.engine import build_diff as _build_diff
from mcp_audit.diff.engine import diff_against_base, diff_revisions

__all__ = ["_build_diff", "diff_against_base", "diff_revisions"]
