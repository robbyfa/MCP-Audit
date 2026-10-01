# Release checklist

## Local preflight

```bash
uv sync --locked
uv run pytest
uv build
```

Install the wheel into a clean environment and verify `mcp-audit --version`, a passing scan, a failing scan, and `policy check`.

## Contract review

- Confirm CLI/package, ruleset, report schema, and manifest schema versions.
- Review golden-output changes explicitly.
- Update `CHANGELOG.md` and every affected rule page.
- Confirm the composite Action references supported major action versions.

## Publish

1. Create and push the matching Git tag, such as `v0.1.1`.
2. Publish the matching GitHub Release. This automatically runs `release.yml`.
3. Verify `pipx install mcp-capdiff` in a clean environment.
4. Run the tagged Action from the demo repository and confirm SARIF appears in Code Scanning.

For the first release, configure a GitHub Actions Pending Trusted Publisher on PyPI before running the workflow:

```text
PyPI project name: mcp-capdiff
Owner: robbyfa
Repository: MCP-Audit
Workflow filename: release.yml
Environment: pypi
```

The GitHub environment must be named `pypi`. Publishing uses OIDC and does not require a `PYPI_TOKEN` secret. Manual workflow dispatches require a release tag; the workflow checks out that immutable tag and verifies that the distribution version matches it.

The PyPI distribution is `mcp-capdiff`; the product remains MCP Audit and the installed command remains `mcp-audit`. Name availability is only guaranteed when the first release is registered.
