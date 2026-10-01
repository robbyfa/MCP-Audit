# Report schema 1.0

MCP Audit uses the same dataclass-backed objects for terminal, JSON, SARIF, manifest, and diff output. JSON reports identify the contract with:

```json
{
  "schema_version": "1.0",
  "report_type": "scan"
}
```

Reports also include the CLI and ruleset versions. Manifests carry `schema_version` and `rules_version`; SARIF uses `semanticVersion` and `properties.rulesVersion` on the tool driver.

`report_type` is either `scan` or `diff`. Scan/report schema and diff schema are both currently `1.0` but evolve independently.

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

Diff reports contain before/after risk, new/removed/changed tools, findings, and canonical `changes`. Each change includes:

- `kind`, such as `capability_widened`, `approval_removed`, or `finding_added`.
- `tool` and registration `context` for stable identity.
- optional `field`, `before`, `after`, and `rule_id` values.
- `classification`: `regression`, `improvement`, or `neutral`.
- policy-derived `blocking` and `warning` flags.
- source `location` where one is available.

The summary includes blocking-regression, warning, and improvement counts. `regression_findings` is retained as a compatibility field and contains newly introduced or severity-increased source findings, not synthetic capability findings.

Finding identity uses rule ID, registration context, tool name, and evidence category. Source line numbers are deliberately excluded so ordinary code movement does not create a new finding.

Additive fields may be introduced in schema `1.x`. Removing or changing the meaning of an existing field requires a new major schema version.
