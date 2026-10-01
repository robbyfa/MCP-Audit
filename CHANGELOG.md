# Changelog

All notable changes follow Keep a Changelog. Releases use semantic versioning for the CLI package; rules and output schemas are versioned independently.

## [Unreleased]

### Added

- Dedicated PyPI Trusted Publishing workflow with tag-pinned builds and OIDC authentication.

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
