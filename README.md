# MCP Audit

MCP Audit is an open-source security regression scanner for Model Context Protocol servers. It extracts tool capabilities and permissions, detects risky cross-tool data flows, compares security posture across Git revisions, and emits CI-friendly evidence.

The first version focuses on Python/FastMCP projects and the core product thesis from the spec: show what an MCP server can do, what changed, and whether the change creates a dangerous capability path.

MCP005 is the capability-graph rule: it identifies when one tool returns classified data and another tool in the same MCP registration context can send it to an external destination. Findings include the source, data classification, sink, destination, path, source evidence, impact, and remediation.

## Install locally

```bash
uv sync
```

Run project commands through `uv run`, or activate the virtual environment with
`source .venv/bin/activate` before using bare commands.

The package also supports isolated CLI installation directly from a checkout:

```bash
pipx install .
mcp-audit --version
mcp-audit scan .
```

The product and CLI are named MCP Audit, while the PyPI distribution is named `mcp-capdiff`:

```bash
pipx install mcp-capdiff
mcp-audit --version
```

## Scan a server

```bash
uv run mcp-audit scan .
```

Scans fail closed when source cannot be read or when no MCP tools are discovered. Use `--allow-empty` only when an empty result is intentional.

Useful output formats:

```bash
uv run mcp-audit scan . --format json
uv run mcp-audit scan . --format sarif --output mcp-audit.sarif
```

## Generate a capability manifest

```bash
uv run mcp-audit manifest .
```

## Compare against a Git baseline

```bash
uv run mcp-audit diff --base origin/main
```

The diff report focuses on security changes: before/after risk, added and changed tools, expanded capabilities, new findings, resolved findings, and approval removal.

## Run tests

```bash
uv run pytest
```

The corpus contains positive, negative, and edge cases under `fixtures/`, including host allowlisting, path-root validation, approval gating, and cross-tool sensitive-data paths.

## GitHub Action

The repository includes a composite action that runs the security diff, uploads SARIF to GitHub Code Scanning, and fails the check when policy thresholds are crossed:

```yaml
permissions:
  actions: read
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0
  - uses: actions/setup-python@v5
    with:
      python-version: "3.12"
  - uses: your-org/mcp-audit@v0.1
    with:
      target: .
      base: origin/main
      policy: mcp-audit.yaml
```

JSON reports and manifests use the versioned schema documented in `docs/report-schema.md`.

The copyable [vulnerable FastMCP demo](examples/vulnerable-fastmcp/) includes four before/after pull-request scenarios and its own Action workflow.

## V0.1 rules

- `MCP001` arbitrary shell execution.
- `MCP002` unrestricted filesystem access.
- `MCP003` arbitrary URL or SSRF surface.
- `MCP004` high-impact side effect without approval.
- `MCP005` sensitive read to external write path.
- `MCP007` unbounded security-sensitive input.
- `MCP010` destructive tool exposed.
- `MCP016` capability escalation in a diff.
- `MCP017` approval removed in a diff.

Each rule's detection behavior, examples, remediation, and limitations are documented in [docs/rules](docs/rules/README.md).

## Demo fixtures

```bash
uv run mcp-audit scan fixtures/safe_server
uv run mcp-audit scan fixtures/vulnerable_server
```

The vulnerable fixture includes a sensitive file read tool, an unrestricted URL fetcher, shell execution, and a destructive operation. MCP Audit should flag the individual findings and the cross-tool path:

```text
read_customer_file -> agent_context -> fetch_url
```

## Policy

The default policy fails on high and critical findings. A minimal policy file can set a risk threshold and suppress reviewed findings:

```yaml
policy:
  ci:
    fail_on:
      - critical
      - high
    max_risk_score: 60

suppress:
  - rule: MCP003
    tool: internal_fetch
    reason: "Network egress is enforced by service mesh"
    expires: 2027-01-31
```

Suppression reasons are required. Expired suppressions no longer hide findings, and `mcp-audit policy check` reports them. See [policy documentation](docs/policy.md).

## Version contracts

CLI, ruleset, report schema, and manifest schema versions evolve independently. See [versioning](docs/versioning.md) and [report schema](docs/report-schema.md).

Passing MCP Audit is technical security evidence, not a legal compliance determination.
