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

## Severity guidelines

| Severity | When to use |
|---|---|
| `critical` | Direct jailbreak, data exfiltration instruction, credential theft |
| `high` | Behavioral manipulation, priority hijacking, excess high-risk permissions |
| `medium` | Subtle misdirection, cross-server bleed risk, moderate over-permission |
| `low` | Informational, best-practice violations with limited exploitability |
