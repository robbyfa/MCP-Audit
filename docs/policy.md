# Policy and suppressions

Policies define CI thresholds and reviewed exceptions:

```yaml
policy:
  ci:
    fail_on: [critical, high]
    max_risk_score: 60
    fail_on_changes:
      - new_critical_finding
      - new_high_finding
      - filesystem_widened
      - network_widened
      - shell_execution_added
      - side_effect_widened
      - approval_removed
      - destructive_capability_added
      - sensitive_external_flow_added
    warn_on_changes:
      - new_medium_finding
      - tool_added
      - sensitivity_increased
      - input_became_unbounded

suppress:
  - rule: MCP003
    tool: internal_fetch
    reason: "Egress is restricted to api.example.com by the service mesh"
    expires: 2027-01-31
```

`reason` is required. `tool` is optional and omission suppresses the rule for all tools. `expires` is optional and must use `YYYY-MM-DD`; after that date the finding is no longer suppressed. `mcp-audit policy check` exits with status `1` when a suppression is expired and status `2` for invalid policy syntax.

Suppressions are policy decisions, not proof that a finding is safe. Prefer a narrow tool-specific suppression with a short expiry.

`fail_on` remains the severity threshold for newly introduced or severity-increased findings. In diff mode, the default policy also blocks filesystem, network, execution, or side-effect widening, approval removal, and destructive capability introduction. It warns on safe tool additions, new medium/low findings, sensitivity increases, and newly unbounded input.

`fail_on_changes` and `warn_on_changes` replace those default change-kind sets when present. Scan mode continues to evaluate the complete scan against `fail_on` and `max_risk_score`; diff mode evaluates only changes from the baseline, so inherited baseline debt does not fail an otherwise neutral pull request.
