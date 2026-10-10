from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from hexswarm import __version__
from hexswarm.agents.orchestrator import Orchestrator
from hexswarm.agents.specialized import build_ctf_agent
from hexswarm.config import load_settings
from hexswarm.llm.router import LLMRouter
from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel
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
    """List every registered tool, its category, risk tier, and whether its binary is installed."""
    table = Table(title="HexSwarm tool registry")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Risk level")
    table.add_column("Binary")
    table.add_column("Installed?")
    for tool in ToolRegistry.all().values():
        if tool.local_only:
            status = "n/a (pure Python)"
        elif tool.is_available():
            status = "yes"
        else:
            status = "no (simulate mode)"
        binary_label = "(local)" if tool.local_only else tool.binary
        table.add_row(tool.name, tool.category, tool.risk_level.value, binary_label, status)
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
    yes: bool = typer.Option(
        False, "--yes", "-y",
        help="Skip the pre-run authorization confirmation prompt (for CI/scripted use).",
    ),
) -> None:
    """Run the full recon -> scan -> exploit -> privesc -> report swarm against a target."""
    settings = load_settings()
    try:
        guard = ScopeGuard.from_file(scope_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Scope error[/red]: {exc}")
        raise typer.Exit(code=1)

    try:
        guard.check_target(target)
    except ScopeViolation as exc:
        console.print(f"[red]Scope error[/red]: {exc}")
        raise typer.Exit(code=1)

    if not yes:
        console.print(
            f"[bold]Engagement[/bold]: {guard.engagement_name}\n"
            f"[bold]Target[/bold]: {target}\n"
            f"[bold]Authorized by[/bold]: {guard.authorized_by or '(not recorded in scope file)'}\n"
            f"[bold]Max risk level[/bold]: {guard.max_risk_level.value}\n"
            "HexSwarm is about to run autonomously (no per-step confirmation) against a real "
            "target. This is only appropriate for a system you own or are explicitly authorized "
            "to test (your own lab, a CTF, an in-scope bug bounty asset, or a signed engagement)."
        )
        if not typer.confirm("Proceed?"):
            console.print("Aborted. Nothing was run.")
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


@app.command()
def ctf(
    goal: str = typer.Option(
        ..., "--goal", "-g",
        help="What kind of challenge this is / what you're looking for, e.g. 'find the flag in this binary'.",
    ),
    file: Path = typer.Option(
        ..., "--file", "-f", help="Path to the local challenge file (binary, image, capture, etc.)."
    ),
    model: str = typer.Option(None, "--model", help="Override the primary LLM model string."),
) -> None:
    """Run the standalone CTF agent against a local challenge file.

    No scope file needed: CTF tools analyze local files and strings, not network
    targets, so there's nothing to authorize against a host allowlist.
    """
    if not file.exists():
        console.print(f"[red]File not found[/red]: {file}")
        raise typer.Exit(code=1)

    settings = load_settings()
    router = LLMRouter(
        primary_model=model or settings.primary_model,
        fallback_models=settings.fallback_models,
        temperature=settings.temperature,
    )

    from hexswarm.memory.findings import FindingsStore

    # CTF tools never touch check_target() (requires_scope_check=False), so this guard
    # exists only to satisfy check_risk(); its allow list is never actually consulted.
    guard = ScopeGuard(
        engagement_name=f"ctf-{file.name}",
        allow=["local-file-analysis"],
        max_risk_level=ToolRiskLevel.READ_ONLY,
    )
    findings = FindingsStore(engagement_name=guard.engagement_name)
    agent = build_ctf_agent(router=router, model=model)

    console.print(f"[bold]HexSwarm CTF agent[/bold] analyzing '[yellow]{file}[/yellow]'...")
    summary = agent.run(goal=goal, target=str(file), guard=guard, findings=findings)
    console.print(f"\n{summary}")


if __name__ == "__main__":
    app()
