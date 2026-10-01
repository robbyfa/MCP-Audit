# Rule precision matrix

The release gate requires positive, negative, guarded, and edge coverage for the differentiating rules.

| Rule | True positive | True negative | Guarded safe | Tricky edge |
| --- | --- | --- | --- | --- |
| MCP001 | `shell_direct` | `safe_server` | `shell_safe_allowlist` | `shell_dynamic_no_shell` detects a dynamic executable without `shell=True` |
| MCP002 | `filesystem_unrestricted` | `sensitive_read_only` | `filesystem_restricted` | `filesystem_guard_after_read` rejects a late guard |
| MCP003 | `url_arbitrary` | fixed URL in demo baseline | `url_allowlisted` | hostname mention and guard-after-request remain findings |
| MCP005 | `sensitive_to_network` | `sensitive_read_only` | constrained source-only server | root corpus proves independent MCP contexts are isolated |
| MCP016 | network expansion diff | unchanged diff | allowlist-added demo resolves risk | a new high-impact tool is an escalation |
| MCP017 | approval-removed diff | preserved approval | approval-added demo resolves risk | capability field change is retained in machine output |

MCP004, MCP007, and MCP010 also have paired approved/bounded and unapproved/unbounded fixtures. The matrix is intentionally tied to fixture and test names so reviewers can audit the claim.

`postgresql_read_only` protects the semantic classifier from matching `post` inside `PostgreSQL`; `sql_destructive` proves that actual `DELETE`/`DROP` semantics still produce MCP004 and MCP010 with relevant evidence.

Discovery is separately benchmarked by `fastmcp_async_annotations`, which must find both plain async `@mcp.tool()` and `@mcp.tool(annotations=ToolAnnotations(...))` decorators. Missing targets, unreadable trees, parse failures, and unexpected zero-tool scans fail closed.

Real-world regression fixtures also cover imported `mcp.tool()(function)` registration, helper-based path containment, SQLite reads, local file modes, and local directory creation. MCP005 requires an actual outbound network destination; local writes and semantic-only action names cannot become exfiltration sinks.
