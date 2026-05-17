"""CLI: yuroo_shield scan 0xADDRESS [--chain ethereum]."""
from __future__ import annotations

import asyncio
import json

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import CHAIN_IDS
from .orchestrator import AgentOrchestrator, RiskLevel

app = typer.Typer(add_completion=False, help="Yuroo Shield AI — contract security scanner")
console = Console()


def _level_color(level: RiskLevel) -> str:
    return {
        RiskLevel.SAFE: "green",
        RiskLevel.LOW: "yellow",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "red",
    }[level]


@app.command()
def scan(
    address: str = typer.Argument(..., help="Contract address (0x...)"),
    chain: str = typer.Option("ethereum", help=f"Chain: {', '.join(CHAIN_IDS)}"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of pretty output"),
) -> None:
    """Run a full security scan against a contract."""
    asyncio.run(_run(address, chain, json_output))


async def _run(address: str, chain: str, json_output: bool) -> None:
    async with AgentOrchestrator() as orch:
        report = await orch.scan_contract(address, chain)

    if json_output:
        console.print_json(json.dumps(report.to_dict()))
        return

    color = _level_color(report.risk_level)
    header = (
        f"[bold]{address}[/bold] on [cyan]{chain}[/cyan]\n"
        f"Risk: [{color}]{report.risk_level.value.upper()}[/{color}] "
        f"({report.risk_score}/100)\n"
        f"[dim]{report.recommendation}[/dim]"
    )
    console.print(Panel(header, title="Yuroo Shield Verdict"))

    if report.summary:
        console.print(Panel(report.summary, title="Summary"))

    table = Table(title="Findings", show_header=True, header_style="bold")
    table.add_column("Agent")
    table.add_column("Signal")
    table.add_column("Severity")
    table.add_column("Detail", overflow="fold")

    for agent_name, output in report.agent_outputs.items():
        for finding in output.get("findings", []) + output.get("signals", []):
            table.add_row(
                agent_name,
                finding.get("name", ""),
                finding.get("severity", ""),
                finding.get("detail", ""),
            )

    if table.row_count:
        console.print(table)
    else:
        console.print("[green]No findings.[/green]")


@app.command()
def chains() -> None:
    """List supported chains."""
    table = Table(title="Supported chains")
    table.add_column("Name")
    table.add_column("Chain ID")
    for name, cid in CHAIN_IDS.items():
        table.add_row(name, str(cid))
    console.print(table)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
    reload: bool = typer.Option(False, help="Enable auto-reload (dev mode)"),
) -> None:
    """Start the Yuroo Shield web UI + JSON API."""
    import uvicorn

    uvicorn.run(
        "yuroo_shield.web:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    app()
