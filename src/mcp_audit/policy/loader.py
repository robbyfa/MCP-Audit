from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from mcp_audit.models.finding import Finding, Severity


SUPPORTED_RULES = {
    "MCP001",
    "MCP002",
    "MCP003",
    "MCP004",
    "MCP005",
    "MCP007",
    "MCP010",
    "MCP016",
    "MCP017",
}


@dataclass(frozen=True, slots=True)
class Suppression:
    rule_id: str
    reason: str
    tool: str | None = None
    expires: date | None = None

    def matches(self, finding: Finding) -> bool:
        return self.rule_id == finding.rule_id and (self.tool is None or self.tool == finding.tool)

    def is_active(self, as_of: date | None = None) -> bool:
        return self.expires is None or self.expires >= (as_of or date.today())


@dataclass(slots=True)
class Policy:
    fail_on: set[Severity] = field(default_factory=lambda: {Severity.CRITICAL, Severity.HIGH})
    max_risk_score: int | None = None
    suppressions: list[Suppression] = field(default_factory=list)

    def expired_suppressions(self, as_of: date | None = None) -> list[Suppression]:
        return [suppression for suppression in self.suppressions if not suppression.is_active(as_of)]


def load_policy(path: str | None) -> Policy:
    if not path:
        return Policy()
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"policy file not found: {policy_path}")
    try:
        payload = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML in policy file: {exc}") from exc
    return _parse_policy(payload)


def _parse_small_yaml_subset(text: str) -> Policy:
    """Compatibility helper retained for callers of the pre-0.1 parser."""
    try:
        payload = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML policy: {exc}") from exc
    return _parse_policy(payload)


def _parse_policy(payload: Any) -> Policy:
    if not isinstance(payload, dict):
        raise ValueError("policy document must be a YAML mapping")
    policy = Policy()
    policy_config = payload.get("policy", {})
    if policy_config and not isinstance(policy_config, dict):
        raise ValueError("policy must be a mapping")
    ci_config = policy_config.get("ci", policy_config) if policy_config else {}
    if ci_config and not isinstance(ci_config, dict):
        raise ValueError("policy.ci must be a mapping")

    if "fail_on" in ci_config:
        values = ci_config["fail_on"]
        if not isinstance(values, list) or not values:
            raise ValueError("policy.ci.fail_on must be a non-empty list")
        policy.fail_on = {Severity.parse(str(value)) for value in values}
    if "max_risk_score" in ci_config:
        score = ci_config["max_risk_score"]
        if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
            raise ValueError("policy.ci.max_risk_score must be an integer from 0 to 100")
        policy.max_risk_score = score

    policy.suppressions = _parse_suppressions(payload.get("suppress", []))
    return policy


def _parse_suppressions(value: Any) -> list[Suppression]:
    if value in ({}, [], None):
        return []
    entries: list[dict[str, Any]] = []
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                raise ValueError("each suppression must be a mapping")
            entries.append(item)
    elif isinstance(value, dict):
        for rule_id, config in value.items():
            if not isinstance(config, dict):
                raise ValueError(f"suppression {rule_id} must be a mapping")
            entries.append({"rule": rule_id, **config})
    else:
        raise ValueError("suppress must be a list or mapping")

    suppressions: list[Suppression] = []
    for entry in entries:
        rule_id = str(entry.get("rule", "")).strip().upper()
        if rule_id not in SUPPORTED_RULES:
            raise ValueError(f"unknown suppression rule: {rule_id or '<empty>'}")
        reason = str(entry.get("reason", "")).strip()
        if not reason:
            raise ValueError(f"suppression {rule_id} requires a non-empty reason")
        tool_value = entry.get("tool")
        tool = str(tool_value).strip() if tool_value is not None else None
        expires = _parse_expiry(entry.get("expires"), rule_id)
        suppressions.append(Suppression(rule_id=rule_id, tool=tool or None, reason=reason, expires=expires))
    return suppressions


def _parse_expiry(value: Any, rule_id: str) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as exc:
        raise ValueError(f"suppression {rule_id} expires must use YYYY-MM-DD") from exc
