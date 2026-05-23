#!/usr/bin/env python3
"""
Batch scan multiple real MCP servers and print a combined findings table.
Usage: python3 batch_scan.py
"""
import asyncio
import sys
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table
from rich import box

from mcpscanner.ingestion.config_file import ConfigFileIngester
from mcpscanner.modules import ALL_STATIC_MODULES
from mcpscanner.models import ToolSchema, Finding

console = Console()

# All servers that require no account and no API key.
# command + args are passed directly to the subprocess.
SERVERS = [
    # ── Official Anthropic / MCP reference servers ────────────────────────────
    ("filesystem",          "npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]),
    ("memory",              "npx", ["-y", "@modelcontextprotocol/server-memory"]),
    ("sequential-thinking", "npx", ["-y", "@modelcontextprotocol/server-sequential-thinking"]),
    ("fetch",               "npx", ["-y", "@modelcontextprotocol/server-fetch"]),
    ("puppeteer",           "npx", ["-y", "@modelcontextprotocol/server-puppeteer"]),
    ("pdf",                 "npx", ["-y", "@modelcontextprotocol/server-pdf"]),
    ("everything",          "npx", ["-y", "@modelcontextprotocol/server-everything"]),
    # ── Community servers ─────────────────────────────────────────────────────
    ("mcp-commands",        "npx", ["-y", "mcp-server-commands"]),
    ("desktop-commander",   "npx", ["-y", "@wonderwhy-er/desktop-commander"]),
    ("shell-server",        "npx", ["-y", "mcp-shell-server"]),
    ("sqlite",              "npx", ["-y", "mcp-server-sqlite", "/tmp/mcpscan_test.db"]),
    ("mcp-filesystem-2",    "npx", ["-y", "mcp-filesystem-server", "/tmp"]),
    ("taskmanager",         "npx", ["-y", "@kazuph/mcp-taskmanager"]),
    ("code-runner",         "npx", ["-y", "mcp-server-code-runner"]),
    ("chart",               "npx", ["-y", "mcp-server-chart"]),
]

SEVERITY_COLORS = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}


@dataclass
class ServerResult:
    name: str
    tools: list[ToolSchema]
    findings: list[Finding]
    error: str | None


async def scan_server(name: str, command: str, args: list[str]) -> ServerResult:
    import os, asyncio, json

    env = {**os.environ}
    cmd = [command, *args]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
        )

        from mcpscanner.ingestion.config_file import _mcp_list_tools, _tool_from_raw
        try:
            raw_tools = await asyncio.wait_for(_mcp_list_tools(proc), timeout=20.0)
        finally:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except Exception:
                proc.kill()

        tools = [_tool_from_raw(t, name, []) for t in raw_tools]
        findings = []
        for module in ALL_STATIC_MODULES:
            findings.extend(module().run(tools))

        return ServerResult(name=name, tools=tools, findings=findings, error=None)

    except Exception as e:
        return ServerResult(name=name, tools=[], findings=[], error=str(e)[:80])


async def main():
    console.print("\n[bold]MCPScanner — Batch Scan[/bold]")
    console.print(f"Scanning [cyan]{len(SERVERS)}[/cyan] MCP servers...\n")

    tasks = [scan_server(name, cmd, args) for name, cmd, args in SERVERS]
    results: list[ServerResult] = await asyncio.gather(*tasks)

    # ── Summary table ─────────────────────────────────────────────────────────
    summary = Table(title="Results", box=box.ROUNDED, show_header=True, header_style="bold")
    summary.add_column("Server", width=22)
    summary.add_column("Status", width=10)
    summary.add_column("Tools", width=6, justify="right")
    summary.add_column("Critical", width=8, justify="right")
    summary.add_column("High", width=6, justify="right")
    summary.add_column("Medium", width=8, justify="right")
    summary.add_column("Low", width=5, justify="right")

    total_tools = total_findings = 0
    for r in results:
        if r.error:
            summary.add_row(r.name, "[dim]failed[/dim]", "-", "-", "-", "-", "-")
            continue

        c = sum(1 for f in r.findings if f.severity == "critical")
        h = sum(1 for f in r.findings if f.severity == "high")
        m = sum(1 for f in r.findings if f.severity == "medium")
        l = sum(1 for f in r.findings if f.severity == "low")

        status = "[green]clean[/green]" if not r.findings else "[red]findings[/red]"
        summary.add_row(
            r.name, status, str(len(r.tools)),
            f"[bold red]{c}[/bold red]" if c else "0",
            f"[red]{h}[/red]" if h else "0",
            f"[yellow]{m}[/yellow]" if m else "0",
            str(l) if l else "0",
        )
        total_tools += len(r.tools)
        total_findings += len(r.findings)

    console.print(summary)
    console.print(f"\nTotal tools scanned: [cyan]{total_tools}[/cyan]  |  Total findings: [red]{total_findings}[/red]\n")

    # ── Detailed findings ─────────────────────────────────────────────────────
    all_findings = [(r, f) for r in results for f in r.findings]
    if not all_findings:
        console.print("[green]No findings across all servers.[/green]")
        return

    console.print("[bold]Findings[/bold]\n")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda x: sev_order.get(x[1].severity, 9))

    for r, f in all_findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        console.print(f"[{color}][{f.severity.upper()}][/{color}]  {f.server}/{f.tool_name}")
        console.print(f"  [dim]Module:[/dim] {f.module}")
        console.print(f"  [dim]Detail:[/dim] {f.detail[:120]}")
        if f.evidence:
            console.print(f"  [dim]Evidence:[/dim] {f.evidence[:120]}")
        console.print()


if __name__ == "__main__":
    asyncio.run(main())
