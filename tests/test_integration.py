"""Integration tests — full pipeline: ingestion → modules → report."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcpscanner import MCPScanner
from mcpscanner.report import Report

FIXTURES = Path(__file__).parent / "fixtures"
POISONED_CFG = str(FIXTURES / "config_poisoned.json")
CLEAN_CFG = str(FIXTURES / "config_clean.json")


# ── Full pipeline via Python API ─────────────────────────────────────────────

class TestFullPipelinePoisoned:
    """Scanner against the poisoned test MCP server."""

    def setup_method(self):
        self.report = MCPScanner(target=POISONED_CFG).run()

    def test_tools_ingested(self):
        assert len(self.report.tools) == 3

    def test_server_name(self):
        assert "poisoned-server" in self.report.servers

    def test_description_poison_found(self):
        dp = [f for f in self.report.findings if f.module == "description_poison"]
        assert dp, "Expected description_poison findings"
        assert any(f.severity == "critical" for f in dp)

    def test_schema_injection_found(self):
        si = [f for f in self.report.findings if f.module == "schema_injection"]
        assert si, "Expected schema_injection findings"

    def test_scope_creep_found(self):
        sc = [f for f in self.report.findings if f.module == "scope_creep"]
        assert sc, "Expected scope_creep findings"

    def test_report_has_summary(self):
        summary = self.report.summary()
        assert "CRITICAL" in summary or "HIGH" in summary

    def test_report_to_json(self):
        data = json.loads(self.report.to_json())
        assert data["finding_count"] > 0
        assert data["servers"] == ["poisoned-server"]

    def test_report_to_markdown(self):
        md = self.report.to_markdown()
        assert "## Findings" in md
        assert "poisoned-server" in md

    def test_report_to_sarif(self):
        sarif = json.loads(self.report.to_sarif())
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"]


class TestFullPipelineClean:
    """Scanner against the clean test MCP server — verifies no false positives."""

    def setup_method(self):
        self.report = MCPScanner(target=CLEAN_CFG).run()

    def test_tools_ingested(self):
        assert len(self.report.tools) == 2

    def test_no_description_poison(self):
        dp = [f for f in self.report.findings if f.module == "description_poison"]
        assert not dp, f"False positive description_poison findings: {dp}"

    def test_no_schema_injection(self):
        si = [f for f in self.report.findings if f.module == "schema_injection"]
        assert not si, f"False positive schema_injection findings: {si}"

    def test_no_scope_creep(self):
        # Clean server has no env credentials — nothing to audit
        sc = [f for f in self.report.findings if f.module == "scope_creep"]
        assert not sc, f"False positive scope_creep findings: {sc}"


# ── Module filtering ──────────────────────────────────────────────────────────

class TestModuleFiltering:
    def test_single_module_only(self):
        scanner = MCPScanner(target=POISONED_CFG, module_names=["description_poison"])
        report = scanner.run()
        modules_present = {f.module for f in report.findings}
        assert modules_present == {"description_poison"}

    def test_two_modules(self):
        scanner = MCPScanner(
            target=POISONED_CFG,
            module_names=["description_poison", "schema_injection"],
        )
        report = scanner.run()
        modules_present = {f.module for f in report.findings}
        assert "scope_creep" not in modules_present
        assert "privilege_bleed" not in modules_present


# ── CLI smoke tests ───────────────────────────────────────────────────────────

class TestCLI:
    def _run(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["mcpscan", *args],
            capture_output=True, text=True,
        )

    def test_cli_poisoned_exits_zero(self):
        result = self._run("--target", POISONED_CFG, "--quiet")
        assert result.returncode == 0

    def test_cli_poisoned_prints_findings(self):
        result = self._run("--target", POISONED_CFG, "--quiet")
        output = result.stdout
        assert "CRITICAL" in output or "HIGH" in output

    def test_cli_json_output(self, tmp_path):
        out = tmp_path / "report.json"
        result = self._run("--target", POISONED_CFG, "--output", str(out))
        assert result.returncode == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["finding_count"] > 0

    def test_cli_markdown_output(self, tmp_path):
        out = tmp_path / "report.md"
        result = self._run("--target", POISONED_CFG, "--output", str(out))
        assert result.returncode == 0
        assert "## Findings" in out.read_text()

    def test_cli_sarif_output(self, tmp_path):
        out = tmp_path / "report.sarif"
        result = self._run("--target", POISONED_CFG, "--output", str(out))
        assert result.returncode == 0
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"

    def test_cli_module_filter(self):
        result = self._run("--target", POISONED_CFG, "--modules", "description_poison", "--quiet")
        assert result.returncode == 0
        # Should not mention schema_injection
        assert "schema_injection" not in result.stdout

    def test_cli_unknown_module_exits_nonzero(self):
        result = self._run("--target", POISONED_CFG, "--modules", "doesnt_exist")
        assert result.returncode != 0

    def test_fail_on_exits_one_when_triggered(self):
        result = self._run("--target", POISONED_CFG, "--fail-on", "high", "--quiet")
        assert result.returncode == 1

    def test_fail_on_exits_zero_when_clean(self):
        result = self._run("--target", CLEAN_CFG, "--fail-on", "high", "--quiet")
        assert result.returncode == 0

    def test_fail_on_critical_passes_when_only_high(self):
        # Only medium findings — --fail-on critical should not trigger
        result = self._run(
            "--target", POISONED_CFG,
            "--modules", "scope_creep",
            "--fail-on", "critical",
            "--quiet",
        )
        assert result.returncode == 0

    def test_fail_on_prints_message(self):
        result = self._run("--target", POISONED_CFG, "--fail-on", "high")
        assert "Exiting with code 1" in result.stdout or "Exiting with code 1" in result.stderr
