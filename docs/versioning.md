# Versioning

MCP Audit maintains four independent versions:

| Contract | Current | Change policy |
| --- | --- | --- |
| CLI/package | `0.1.3` | Semantic versioning; pre-1.0 minor releases may change CLI behavior |
| Ruleset | `0.1` | Minor adds or materially changes rules; patch corrects implementation without intended semantic change |
| JSON report schema | `1.0` | Minor changes are additive; major changes may remove fields or change meaning |
| Manifest schema | `1.0` | Minor changes are additive; major changes may remove fields or change meaning |

The `mcp-capdiff` distribution version is reported by `mcp-audit --version`. JSON and SARIF include the CLI version and ruleset version. Manifests include their schema and ruleset versions.

Rule IDs are stable. A rule may be refined within a ruleset minor version, but an incompatible meaning requires a new rule ID or a documented major ruleset change.
