# MCP Audit rules

Rules are versioned independently from the CLI. MCP Audit `0.2.2` ships ruleset `0.2`.

| Rule | Default severity | Purpose |
| --- | --- | --- |
| [MCP001](MCP001.md) | Critical | Arbitrary shell or code execution |
| [MCP002](MCP002.md) | High | Unrestricted filesystem access |
| [MCP003](MCP003.md) | High | Arbitrary outbound URL or SSRF surface |
| [MCP004](MCP004.md) | Medium/High | High-impact side effect without approval |
| [MCP005](MCP005.md) | High/Critical | Sensitive-data path to an external sink |
| [MCP007](MCP007.md) | Medium | Unbounded security-sensitive input |
| [MCP010](MCP010.md) | High | Destructive tool without approval |

MCP016 and MCP017 were v0.1 synthetic diff findings. In v0.2 their semantics are represented by structured `capability_widened` and `approval_removed` changes, keeping SARIF reserved for source-level findings.

Static findings are evidence for review, not proof of exploitability or legal compliance.
