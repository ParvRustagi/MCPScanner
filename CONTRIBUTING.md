# Contributing to MCPScanner

## Adding a new attack module

1. Subclass `BaseAttackModule` in `mcpscanner/modules/base.py`
2. Implement `run(schemas: list[ToolSchema]) -> list[Finding]`
3. Register it in `mcpscanner/modules/__init__.py` (both `ALL_STATIC_MODULES` and `MODULE_REGISTRY`)
4. Add at least one unit test in `tests/test_modules.py`
5. If the module needs a fixture MCP server, add it under `tests/fixtures/`

## Running tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Releasing (maintainers)

Releases publish to PyPI as [`mcpscan`](https://pypi.org/p/mcpscan) via GitHub
Actions **Trusted Publishing** (OIDC) — no API tokens are stored anywhere.

1. Bump `version` in `pyproject.toml` and commit to `main`.
2. Create a GitHub Release with a tag like `v0.1.0`
   (`gh release create v0.1.0 --generate-notes`).
3. The `Publish to PyPI` workflow runs automatically: it tests, builds,
   `twine check`s, and publishes to PyPI.

One-time setup on PyPI (already done for the first release): add a Trusted
Publisher under the project with owner `ParvRustagi`, repo `MCPScanner`,
workflow `publish.yml`, environment `pypi`.

## Severity guidelines

| Severity | When to use |
|---|---|
| `critical` | Direct jailbreak, data exfiltration instruction, credential theft |
| `high` | Behavioral manipulation, priority hijacking, excess high-risk permissions |
| `medium` | Subtle misdirection, cross-server bleed risk, moderate over-permission |
| `low` | Informational, best-practice violations with limited exploitability |
