# MCP Audit

**Security regression CI for MCP servers.**

MCP Audit tells you when a pull request makes an MCP server more dangerous.

**MCP Audit understands whether a change makes your MCP server safer, riskier, or simply different.**

**Blocking regression detected**

Filesystem scope widened from allowlisted to unrestricted.

![MCP Audit blocking an unrestricted filesystem regression](https://raw.githubusercontent.com/robbyfa/MCP-Audit/v0.2.3/docs/assets/demo/blocking-regression.png)

**No security regression**

A new read-only tool was added; MCP Audit warns but does not block.

![MCP Audit allowing a harmless read-only tool](https://raw.githubusercontent.com/robbyfa/MCP-Audit/v0.2.3/docs/assets/demo/harmless-tool-added.png)

**Security improvement**

Filesystem access was narrowed and previous findings were resolved.

![MCP Audit reporting resolved filesystem findings](https://raw.githubusercontent.com/robbyfa/MCP-Audit/v0.2.3/docs/assets/demo/security-improvement.png)

Add it to a pull-request workflow:

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

  - uses: robbyfa/MCP-Audit@v0.2.3
    with:
      path: .
      baseline: origin/main
```

The Action writes a security-diff summary to the workflow run, uploads new source findings to GitHub Code Scanning, and fails only when the change introduces a blocking regression.

See the Action on three real pull requests:

- [Filesystem access widens and CI fails](https://github.com/robbyfa/MCP-Audit/pull/1)
- [Filesystem access narrows and CI passes](https://github.com/robbyfa/MCP-Audit/pull/2)
- [A harmless read-only tool is added and CI passes](https://github.com/robbyfa/MCP-Audit/pull/3)

## Install the CLI

```bash
pipx install mcp-capdiff
mcp-audit scan .
```

The product and CLI are named MCP Audit; the PyPI distribution is named `mcp-capdiff`.

Version 0.2 focuses on Python/FastMCP projects and one CI question: did this change make the MCP server more dangerous?

## Develop locally

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
uv run mcp-audit diff --baseline origin/main .
uv run mcp-audit diff origin/main HEAD
```

The diff compares tools by registration context and name, classifies capability and finding changes as regressions, improvements, or neutral changes, and exits `1` only for blocking regressions. Operational and baseline errors exit `2`.

Machine and CI outputs use the same structured change model:

```bash
uv run mcp-audit diff --baseline origin/main . --format json
uv run mcp-audit diff --baseline origin/main . --format markdown
uv run mcp-audit diff --baseline origin/main . \
  --sarif-output mcp-audit.sarif \
  --summary-output mcp-audit-summary.md
```

## Run tests

```bash
uv run pytest
```

The corpus contains positive, negative, and edge cases under `fixtures/`, including host allowlisting, path-root validation, approval gating, and cross-tool sensitive-data paths.

## GitHub Action options

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
  - uses: robbyfa/MCP-Audit@v0.2.3
    with:
      path: .
      baseline: origin/main
```

Add `policy: mcp-audit.yaml` when the repository needs custom blocking rules or reviewed suppressions.

JSON reports and manifests use the versioned schema documented in `docs/report-schema.md`.

The copyable [vulnerable FastMCP demo](examples/vulnerable-fastmcp/) includes four before/after pull-request scenarios and its own Action workflow.

## Rules

- `MCP001` arbitrary shell execution.
- `MCP002` unrestricted filesystem access.
- `MCP003` arbitrary URL or SSRF surface.
- `MCP004` high-impact side effect without approval.
- `MCP005` sensitive read to external write path.
- `MCP007` unbounded security-sensitive input.
- `MCP010` destructive tool exposed.

Capability widening and approval removal are first-class semantic diff changes in v0.2 rather than synthetic source findings. SARIF therefore remains focused on newly introduced MCP001-MCP010 findings, while the job summary reports capability and policy changes.

MCP005 is the capability-graph rule: it identifies when one tool returns classified data and another tool in the same MCP registration context can send it to an external destination. Findings include the source, data classification, sink, destination, path, source evidence, impact, and remediation.

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
    fail_on_changes:
      - filesystem_widened
      - network_widened
      - shell_execution_added
      - side_effect_widened
      - approval_removed
      - destructive_capability_added
    warn_on_changes:
      - tool_added
      - input_became_unbounded

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
