# Rule precision matrix

The release gate requires positive, negative, guarded, and edge coverage for the differentiating rules.

| Rule | True positive | True negative | Guarded safe | Tricky edge |
| --- | --- | --- | --- | --- |
| MCP001 | `shell_direct` | `safe_server` | `shell_safe_allowlist` | `shell_dynamic_no_shell` and `benchmark_semantics` detect dynamic subprocess and pexpect execution |
| MCP002 | `filesystem_unrestricted` | `sensitive_read_only` | `filesystem_restricted` | `filesystem_guard_after_read` rejects a late guard while generic `.replace()` calls remain non-filesystem operations |
| MCP003 | `url_arbitrary` | fixed URL in demo baseline | `url_allowlisted` | hostname mention and guard-after-request remain findings |
| MCP005 | `sensitive_to_network` | `sensitive_read_only` | constrained source-only server | root corpus proves independent MCP contexts are isolated |

MCP004, MCP007, and MCP010 also have paired approved/bounded and unapproved/unbounded fixtures. The matrix is intentionally tied to fixture and test names so reviewers can audit the claim.

`postgresql_read_only` protects the semantic classifier from matching `post` inside `PostgreSQL`; `sql_destructive` proves that actual `DELETE`/`DROP` semantics still produce MCP004 and MCP010 with relevant evidence.

Discovery is separately benchmarked by `fastmcp_async_annotations`, which must find both plain async `@mcp.tool()` and `@mcp.tool(annotations=ToolAnnotations(...))` decorators. Missing targets, unreadable trees, parse failures, and unexpected zero-tool scans fail closed.

Real-world regression fixtures also cover imported `mcp.tool()(function)` registration, helper-based path containment, SQLite reads, local file modes, local directory creation, `pexpect.spawn`, typed `Path.replace`, and ordinary string/datetime `.replace()` calls. MCP005 requires an actual outbound network destination; local writes and semantic-only action names cannot become exfiltration sinks. Read/list/status tools and incidental destructive words in documentation are negative cases for side-effect inference.

Security diff coverage separately proves widening and narrowing for filesystem, network, execution, and side effects; approval and destructive directionality; tool additions/removals; finding additions and severity changes; parameter bounds; registration-context identity; two-revision Git operation; exit codes; Markdown; JSON; and SARIF.
