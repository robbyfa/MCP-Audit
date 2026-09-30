from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.models.finding import Severity


@dataclass(slots=True)
class Policy:
    fail_on: set[Severity] = field(default_factory=lambda: {Severity.CRITICAL, Severity.HIGH})
    max_risk_score: int | None = None
    suppressions: set[tuple[str, str | None]] = field(default_factory=set)


def load_policy(path: str | None) -> Policy:
    if not path:
        return Policy()
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"policy file not found: {policy_path}")
    text = policy_path.read_text(encoding="utf-8")
    return _parse_small_yaml_subset(text)


def _parse_small_yaml_subset(text: str) -> Policy:
    policy = Policy()
    active_key: str | None = None
    suppress_rule: str | None = None
    custom_fail_on = False
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":") and not stripped.startswith("-"):
            active_key = stripped[:-1]
            if active_key.startswith("MCP"):
                suppress_rule = active_key
            continue
        if active_key == "fail_on" and stripped.startswith("-"):
            if not custom_fail_on:
                policy.fail_on.clear()
                custom_fail_on = True
            severity = stripped.removeprefix("-").strip()
            policy.fail_on.add(Severity.parse(severity))
        if stripped.startswith("max_risk_score:"):
            _, value = stripped.split(":", 1)
            policy.max_risk_score = int(value.strip())
        if active_key == "suppress" and stripped.startswith("MCP"):
            suppress_rule = stripped.split(":", 1)[0]
            policy.suppressions.add((suppress_rule, None))
        elif suppress_rule and stripped.startswith("tool:"):
            _, tool = stripped.split(":", 1)
            policy.suppressions.add((suppress_rule, tool.strip().strip('"')))
    return policy
