from __future__ import annotations

from collections.abc import Sequence


ORDERINGS: dict[str, Sequence[str]] = {
    "filesystem": ("none", "fixed_file", "allowlisted_files", "directory", "multiple_directories", "unrestricted"),
    "network": ("none", "allowlisted_hosts", "unrestricted_outbound"),
    "execution": ("none", "fixed", "shell", "arbitrary_code"),
    "side_effect": ("none", "local_write", "external_write", "destructive_action"),
    "sensitivity": ("public", "internal", "confidential", "pii", "financial", "secret"),
}


def compare_capability(field: str, before: object, after: object) -> int | None:
    """Return -1 for narrower, 0 for equal, 1 for wider, or None when unordered."""
    if before == after:
        return 0
    if field in ORDERINGS:
        ordering = ORDERINGS[field]
        try:
            return _sign(ordering.index(str(after)) - ordering.index(str(before)))
        except ValueError:
            return None
    if field == "data_access":
        before_values = set(before or [])
        after_values = set(after or [])
        if before_values < after_values:
            return 1
        if after_values < before_values:
            return -1
    if field == "network_destination":
        if before in {None, "none"} and after not in {None, "none"}:
            return 1
        if after in {None, "none"} and before not in {None, "none"}:
            return -1
        if before != "unrestricted external URL" and after == "unrestricted external URL":
            return 1
        if before == "unrestricted external URL" and after != "unrestricted external URL":
            return -1
    return None


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)
