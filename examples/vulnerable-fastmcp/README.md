# Vulnerable FastMCP demo

This directory is a copyable sample repository for demonstrating MCP Audit in pull requests. Each scenario contains a reviewed `before.py` and proposed `after.py`.

| Scenario | Expected diff |
| --- | --- |
| `unrestricted_fetch` | MCP003, MCP007, MCP016 |
| `filesystem_expansion` | MCP002, MCP007, MCP016 |
| `approval_removed` | MCP004, MCP010, MCP017 |
| `network_allowlist_added` | MCP003 and MCP007 resolved |

To turn one scenario into a local demo repository, copy `before.py` to `server.py`, commit it, replace it with `after.py`, and run:

```bash
mcp-audit diff --base HEAD
```

The included workflow is ready for a repository created from this directory after the `v0.1.0` action tag is published.
