# Changelog

All notable changes follow Keep a Changelog. Releases use semantic versioning for the CLI package; rules and output schemas are versioned independently.

## [Unreleased]

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
