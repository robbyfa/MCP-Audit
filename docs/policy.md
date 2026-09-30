# Policy and suppressions

Policies define CI thresholds and reviewed exceptions:

```yaml
policy:
  ci:
    fail_on: [critical, high]
    max_risk_score: 60

suppress:
  - rule: MCP003
    tool: internal_fetch
    reason: "Egress is restricted to api.example.com by the service mesh"
    expires: 2027-01-31
```

`reason` is required. `tool` is optional and omission suppresses the rule for all tools. `expires` is optional and must use `YYYY-MM-DD`; after that date the finding is no longer suppressed. `mcp-audit policy check` exits with status `1` when a suppression is expired and status `2` for invalid policy syntax.

Suppressions are policy decisions, not proof that a finding is safe. Prefer a narrow tool-specific suppression with a short expiry.
