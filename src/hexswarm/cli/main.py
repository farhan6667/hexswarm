from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from hexswarm import __version__
from hexswarm.agents.orchestrator import Orchestrator
from hexswarm.config import load_settings
from hexswarm.llm.router import LLMRouter
from hexswarm.safety.guard import ScopeGuard, ScopeViolation
from hexswarm.tools.base import ToolRegistry

app = typer.Typer(
    name="hexswarm",
    help="A swarm-of-agents framework for AI-driven offensive security research.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def version() -> None:
    """Print the installed HexSwarm version."""
    console.print(f"hexswarm {__version__}")


@app.command(name="tools")
def list_tools() -> None:
    """List every registered tool, its risk tier, and whether its binary is installed."""
    table = Table(title="HexSwarm tool registry")
    table.add_column("Name")
    table.add_column("Risk level")
    table.add_column("Binary")
    table.add_column("Installed?")
    for tool in ToolRegistry.all().values():
        installed = "yes" if tool.is_available() else "no (simulate mode)"
        table.add_row(tool.name, tool.risk_level.value, tool.binary, installed)
    console.print(table)


@app.command(name="scope-check")
def scope_check(
    scope_file: Path = typer.Argument(..., help="Path to a scope YAML file."),
    target: str = typer.Argument(..., help="Target to validate against the scope."),
) -> None:
    """Validate that a target is authorized under a given scope file, without running anything."""
    try:
        guard = ScopeGuard.from_file(scope_file)
        guard.check_target(target)
    except (FileNotFoundError, ValueError, ScopeViolation) as exc:
        console.print(f"[red]REJECTED[/red]: {exc}")
        raise typer.Exit(code=1)
    console.print(f"[green]AUTHORIZED[/green]: '{target}' is in scope for '{guard.engagement_name}'.")


@app.command()
def run(
    goal: str = typer.Option(..., "--goal", "-g", help="High-level natural-language objective."),
    target: str = typer.Option(..., "--target", "-t", help="Target host, IP, CIDR, or URL."),
    scope_file: Path = typer.Option(..., "--scope", "-s", help="Path to a scope YAML file."),
    model: str = typer.Option(None, "--model", help="Override the primary LLM model string."),
    report_out: Path = typer.Option(
        Path("hexswarm_report.md"), "--report-out", help="Where to write the final Markdown report."
    ),
    findings_out: Path = typer.Option(
        None, "--findings-out", help="Optional JSON path to persist raw findings."
    ),
) -> None:
    """Run the full recon -> scan -> exploit -> privesc -> report swarm against a target."""
    settings = load_settings()
    try:
        guard = ScopeGuard.from_file(scope_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Scope error[/red]: {exc}")
        raise typer.Exit(code=1)

    router = LLMRouter(
        primary_model=model or settings.primary_model,
        fallback_models=settings.fallback_models,
        temperature=settings.temperature,
    )

    from hexswarm.memory.findings import FindingsStore

    findings = FindingsStore(engagement_name=guard.engagement_name, persist_path=findings_out)

    orchestrator = Orchestrator(
        router=router,
        scope_guard=guard,
        findings=findings,
        human_in_the_loop=settings.human_in_the_loop,
    )

    console.print(f"[bold]HexSwarm[/bold] running engagement '[cyan]{guard.engagement_name}[/cyan]' "
                  f"against '[yellow]{target}[/yellow]'...")
    result = orchestrator.run(goal=goal, target=target)

    for phase, summary in result.phase_summaries.items():
        console.print(f"\n[bold magenta]{phase.upper()}[/bold magenta]\n{summary}")

    report_out.write_text(result.report_markdown, encoding="utf-8")
    console.print(f"\n[green]Report written to {report_out}[/green]")


if __name__ == "__main__":
    app()
