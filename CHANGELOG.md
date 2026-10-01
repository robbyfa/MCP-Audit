# Changelog

All notable changes follow Keep a Changelog. Releases use semantic versioning for the CLI package; rules and output schemas are versioned independently.

## [Unreleased]

## [0.2.1] - 2026-10-01

### Changed

- Make GitHub job summaries immediately scannable with distinct regression, warning-only, and clean status labels.
- Present improvements and resolved findings in the same structured table format as regressions.
- Lead the README with three public pull-request examples that demonstrate blocking, warning-only, and improving changes.

### Fixed

- Suppress the internal Action smoke-test summary so pull requests show one user-facing MCP Audit summary.
- Give the public check the descriptive name `MCP Security Regression Check`.

### Verified

- 91 automated tests, including explicit Markdown contracts for blocking regressions, warning-only changes, and improvements.

## [0.2.0] - 2026-10-01

### Added

- First-class security diff model with deterministic regression, improvement, and neutral classifications.
- Explicit capability orderings for filesystem, network, execution, side effects, sensitivity, approval, destructive behavior, and input bounds.
- Stable tool identity based on registration context and name, plus line-independent finding identity.
- `mcp-audit diff --baseline BASE PATH` and `mcp-audit diff BASE CURRENT` Git workflows.
- Versioned JSON change contract, Markdown job summaries, and SARIF containing only newly introduced or severity-increased source findings.
- Configurable semantic policy events such as `filesystem_widened`, `approval_removed`, and `new_high_finding`.

### Changed

- Diff exit code `1` now means a blocking security regression; operational, configuration, and baseline failures remain exit code `2`.
- The GitHub Action now writes a concise Step Summary and uploads source-level SARIF from the same evaluated diff.
- Capability widening and approval removal are structured changes instead of synthetic MCP016/MCP017 findings.
- Ruleset version advances to `0.2`; scan, manifest, and security-diff schemas remain independently versioned at `1.0`.

### Verified

- Directionality tests cover widening and narrowing, approval and destructive changes, findings and severity changes, safe and dangerous tool additions, removals, parameter bounds, and registration contexts.
- End-to-end Git tests cover working-tree baselines, two-revision comparisons, pass/fail/error exits, Markdown, JSON, and SARIF.

## [0.1.3] - 2026-10-01

### Fixed

- Stop ordinary string, datetime, and other object `.replace()` calls from being classified as filesystem writes; retain detection for `os.replace(...)` and statically known `Path.replace(...)` calls.
- Detect model-controlled interactive process execution through `pexpect.spawn(...)` and `pexpect.spawnu(...)`.
- Require action verbs for semantic external-write inference so nouns such as `email` and `message` do not turn list/read tools into writes.
- Prefer read-only tool names and explicit negation over incidental destructive words in descriptions while retaining destructive SQL detection for execution tools.

### Verified

- 71 automated tests, including positive controls for shell execution, filesystem replacement, destructive actions, and external writes.
- `metabase-mcp` and `mcp_agent_mail`: string and datetime replacement no longer produce MCP002 findings.
- `interactive-terminal-mcp`: `spawn_process` is classified as shell execution and produces MCP001 evidence at `pexpect.spawn(...)`.
- `MCP-PostgreSQL-Ops` and `winremote-mcp`: the read-only statistics tool and GUI `Type` tool no longer produce MCP004/MCP010 findings.
- The 14-repository benchmark covered 888 discovered tools; interprocedural network propagation remains deferred for a later release.

## [0.1.2] - 2026-10-01

### Fixed

- Discover tools registered with `mcp.tool()(function)`, including functions imported from scanned project modules; unresolved static registrations now fail closed.
- Require a concrete outbound network destination before MCP005 can classify a tool as an exfiltration sink.
- Propagate approved-root guarantees from path-validation helpers such as `_resolve(path)` to later filesystem operations.
- Classify `open(..., "w")`, directory creation, and local filesystem mutations as local writes instead of reads or external writes.

### Verified

- `python-fastmcp-server`: 3 programmatically registered tools discovered instead of a zero-tool result.
- `sqlite-explorer-fastmcp-mcp-server`: 3 read-only tools, 0 side-effect or MCP005 findings.
- `obsidian-mcp`: helper-scoped filesystem tools recognized as allowlisted; only 3 findings remain.
- `smart_terminal_mcp`: critical execution findings preserved, write-mode evidence corrected, and no MCP005 paths remain.

## [0.1.1] - 2026-10-01

### Added

- Dedicated PyPI Trusted Publishing workflow with tag-pinned builds and OIDC authentication.

### Changed

- Rename the PyPI distribution to `mcp-capdiff` while preserving the MCP Audit product name, `mcp_audit` import package, and `mcp-audit` command.
- Prepare version `0.1.1` so the public `v0.1.0` tag remains immutable.

## [0.1.0] - 2026-10-01

### Fixed

- Prevent `PostgreSQL` from being misclassified as an HTTP `POST` side effect.
- Attach destructive semantic evidence to MCP004 and MCP010 instead of unrelated database-read evidence.
- Fail closed on inaccessible source trees and zero-tool scans instead of reporting a false PASS.

### Added

- Discovery benchmark for async `@mcp.tool()` functions with FastMCP `ToolAnnotations`.
- Explicit `--allow-empty` escape hatch for intentional zero-tool scans.
- Python/FastMCP source discovery and capability extraction.
- Nine security and regression rules in ruleset `0.1`.
- Cross-tool sensitive-data path detection with MCP-context isolation.
- Terminal, JSON, SARIF, manifest, and Git security-diff output.
- Versioned report and manifest schema `1.0`.
- Policy thresholds and reasoned, expiring suppressions.
- Composite GitHub Action with Code Scanning upload.

### Verified

- External PostgreSQL MCP benchmark: 20 tools discovered, 6 legitimate findings, no known false positives from `PostgreSQL` token matching, and no false PASS.
