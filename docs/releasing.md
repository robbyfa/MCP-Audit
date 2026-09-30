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

1. Configure a PyPI trusted publisher for this repository.
2. Publish the wheel and source distribution from `dist/`.
3. Create and push the matching Git tag, such as `v0.1.0`.
4. Verify `pipx install mcp-audit` in a clean environment.
5. Run the tagged Action from the demo repository and confirm SARIF appears in Code Scanning.

The `mcp-audit` project name currently has no package JSON endpoint on PyPI, but availability is only guaranteed when the first release is registered.
