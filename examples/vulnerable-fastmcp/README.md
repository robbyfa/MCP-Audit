# Vulnerable FastMCP demo

This directory is a copyable sample repository for demonstrating MCP Audit in pull requests. Each scenario contains a reviewed `before.py` and proposed `after.py`.

`server.py` is the safe baseline used by the public regression demo. `dangerous_server.py` is intentionally unrestricted so a separate pull request can demonstrate that narrowing access is reported as an improvement rather than a failure.

| Scenario | Expected diff |
| --- | --- |
| `unrestricted_fetch` | Network widening, MCP003, and MCP007 |
| `filesystem_expansion` | Filesystem widening, MCP002, and MCP007 |
| `approval_removed` | Approval removal, MCP004, and MCP010 |
| `network_allowlist_added` | MCP003 and MCP007 resolved |

To turn one scenario into a local demo repository, copy `before.py` to `server.py`, commit it, replace it with `after.py`, and run:

```bash
mcp-audit diff --baseline HEAD .
```

The included workflow uses the v0.2.2 Action and writes both SARIF annotations and a Markdown job summary.
