# Report schema 1.0

MCP Audit uses the same dataclass-backed objects for terminal, JSON, SARIF, manifest, and diff output. JSON reports identify the contract with:

```json
{
  "schema_version": "1.0",
  "report_type": "scan"
}
```

`report_type` is either `scan` or `diff`.

## Finding contract

Every finding includes:

- `rule_id`, `title`, and `severity` for identity and prioritization.
- `tool` and `location` for the affected MCP surface.
- `message` describing what was detected.
- `impact` describing the security consequence.
- `recommendation` describing the expected remediation.
- `evidence`, a list of typed source locations and snippets.
- `path`, `data_classification`, and `destination` for capability-graph findings.

## Diff contract

Diff reports contain before/after risk, new/removed/changed tools, field-level capability changes, new findings, resolved findings, and synthetic regression findings (`MCP016` and `MCP017`). Policies are evaluated against new and regression findings, not the entire current scan.

Additive fields may be introduced in schema `1.x`. Removing or changing the meaning of an existing field requires a new major schema version.
