from __future__ import annotations
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

from .core import MCPScanner
from .modules import MODULE_REGISTRY

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
}


@click.command(name="mcpscan")
@click.option("--target", "-t", required=True, help="Path to MCP config JSON or live server URL")
@click.option("--live", "-l", is_flag=True, default=False, help="Enable live attacker LLM probe")
@click.option("--attacker", default="anthropic", show_default=True,
              type=click.Choice(["anthropic", "openai", "gemini", "ollama"], case_sensitive=False),
              help="LLM provider for live probe")
@click.option("--modules", "-m", default=None,
              help="Comma-separated list of modules to run (default: all static)")
@click.option("--output", "-o", default=None,
              help="Output file path (.json, .md, or 'sarif'). Omit for terminal output.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress rich output, print only findings")
def main(target: str, live: bool, attacker: str, modules: str | None, output: str | None, quiet: bool) -> None:
    """MCPScanner — agentic security scanner for MCP servers."""
    module_names: list[str] | None = None
    if modules:
        module_names = [m.strip() for m in modules.split(",")]
        unknown = [m for m in module_names if m not in MODULE_REGISTRY]
        if unknown:
            console.print(f"[red]Unknown modules: {', '.join(unknown)}[/red]")
            console.print(f"Available: {', '.join(MODULE_REGISTRY)}")
            sys.exit(1)

    if not quiet:
        console.print(f"\n[bold]MCPScanner[/bold] — scanning [cyan]{target}[/cyan]")
        if live:
            console.print(f"  Live probe enabled  (provider: {attacker})")
        if module_names:
            console.print(f"  Modules: {', '.join(module_names)}")
        console.print()

    scanner = MCPScanner(
        target=target,
        live=live,
        attacker_provider=attacker,
        module_names=module_names,
    )

    try:
        report = scanner.run()
    except Exception as e:
        console.print(f"[red]Scan failed:[/red] {e}")
        sys.exit(1)

    if output:
        _write_output(report, output)
        if not quiet:
            console.print(f"\n[green]Report written to {output}[/green]")
        return

    if quiet:
        print(report.summary())
        return

    _print_rich_report(report)


def _write_output(report, path: str) -> None:
    p = Path(path)
    if path == "sarif" or p.suffix == ".sarif":
        content = report.to_sarif()
    elif p.suffix == ".json":
        content = report.to_json()
    elif p.suffix == ".md":
        content = report.to_markdown()
    else:
        # Default to JSON for unknown extensions
        content = report.to_json()
    p.write_text(content)


def _print_rich_report(report) -> None:
    console.print(f"[bold]Servers:[/bold] {len(report.servers)}  "
                  f"[bold]Tools:[/bold] {len(report.tools)}  "
                  f"[bold]Findings:[/bold] {len(report.findings)}")

    if report.servers:
        console.print(f"[dim]Servers: {', '.join(report.servers)}[/dim]\n")

    if not report.findings:
        console.print("[green]No findings.[/green]")
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(report.findings, key=lambda f: severity_order.get(f.severity, 9))

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Sev", width=8)
    table.add_column("Module", width=20)
    table.add_column("Server/Tool", width=30)
    table.add_column("Title")

    for f in sorted_findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity.upper()}[/{color}]",
            f.module,
            f"{f.server}/{f.tool_name}",
            f.title,
        )
    console.print(table)

    console.print()
    for i, f in enumerate(sorted_findings, 1):
        color = SEVERITY_COLORS.get(f.severity, "white")
        console.print(f"[{color}][{f.severity.upper()}][/{color}] {f.title}")
        console.print(f"  [dim]Detail:[/dim] {f.detail}")
        if f.evidence:
            console.print(f"  [dim]Evidence:[/dim] {f.evidence[:200]}")
        if f.recommendation:
            console.print(f"  [dim]Fix:[/dim] {f.recommendation}")
        if f.confidence is not None:
            note = " (needs_review)" if f.needs_review else ""
            console.print(f"  [dim]Confidence:[/dim] {f.confidence:.0%}{note}")
        console.print()


if __name__ == "__main__":
    main()
