from __future__ import annotations

import os
import urllib.error
import urllib.request
from pathlib import Path

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
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

RISK_LEVEL_CHOICES = ["read_only", "active_recon", "intrusive", "exploit", "post_exploit"]

MODEL_PRESETS = {
    "1": ("Ollama (local, free, no API key)", "ollama/llama3.1", None),
    "2": ("Anthropic Claude", "anthropic/claude-sonnet-5", "ANTHROPIC_API_KEY"),
    "3": ("OpenAI", "openai/gpt-4o", "OPENAI_API_KEY"),
}


@app.command()
def version() -> None:
    """Print the installed HexSwarm version."""
    console.print(f"hexswarm {__version__}")


@app.command()
def init(
    env_path: Path = typer.Option(Path(".env"), "--env-out", help="Where to write the model config."),
    scope_path: Path = typer.Option(Path("scope.yaml"), "--scope-out", help="Where to write the scope file."),
) -> None:
    """Interactive setup wizard: configure a model and write a scope file in one guided pass.

    Equivalent to hand-editing .env.example and scope.example.yaml yourself, but without having
    to already know the exact keys and risk-level vocabulary HexSwarm expects.
    """
    console.print(Panel.fit(
        "[bold]HexSwarm setup[/bold]\nA couple of questions, then you're ready to run.",
        border_style="cyan",
    ))

    # --- Step 1: model ---
    console.print("\n[bold]1. Which model should HexSwarm use?[/bold]")
    for key, (label, _, _) in MODEL_PRESETS.items():
        console.print(f"  {key}) {label}")
    console.print("  4) Something else (enter a LiteLLM model string manually)")
    choice = typer.prompt("Choice", default="1")

    api_key_line = ""
    if choice in MODEL_PRESETS:
        label, model_string, env_var = MODEL_PRESETS[choice]
        if env_var:
            console.print(
                f"[dim]{label} needs {env_var}. It's written to your local .env only, never sent "
                "anywhere but to that provider's own API with your requests.[/dim]"
            )
            key_value = typer.prompt(
                f"Paste your {env_var} now (or press Enter to add it later)",
                default="",
                hide_input=True,
                show_default=False,
            )
            if key_value:
                api_key_line = f"{env_var}={key_value}\n"
    else:
        model_string = typer.prompt("Model string (provider/model, e.g. ollama/mistral)")

    # --- Step 2: scope ---
    console.print("\n[bold]2. What's this engagement called?[/bold]")
    engagement_name = typer.prompt("Engagement name", default="my-engagement")

    console.print(
        "\n[bold]3. What's in scope?[/bold] Enter hosts, IPs, CIDRs, or domain globs one at a "
        "time. Blank line when done."
    )
    allow: list[str] = []
    while True:
        entry = typer.prompt(f"  Allow entry #{len(allow) + 1} (blank to finish)", default="", show_default=False)
        if not entry:
            if not allow:
                console.print("[yellow]At least one entry is required, HexSwarm refuses an empty scope.[/yellow]")
                continue
            break
        allow.append(entry)

    console.print("\n[bold]4. Maximum risk level for this engagement?[/bold]")
    for i, level in enumerate(RISK_LEVEL_CHOICES, start=1):
        console.print(f"  {i}) {level}")
    risk_choice = typer.prompt("Choice", default="3")
    try:
        max_risk_level = RISK_LEVEL_CHOICES[int(risk_choice) - 1]
    except (ValueError, IndexError):
        max_risk_level = "intrusive"

    authorized_by = typer.prompt("\n5. Authorized by (your name / engagement letter ref)", default="")

    # --- Write files ---
    if env_path.exists() and not typer.confirm(f"\n{env_path} already exists. Overwrite?", default=False):
        console.print(f"[yellow]Skipped writing {env_path}.[/yellow]")
    else:
        env_path.write_text(
            f"HEXSWARM_PRIMARY_MODEL={model_string}\n"
            "HEXSWARM_FALLBACK_MODELS=\n"
            f"{api_key_line}"
            "HEXSWARM_HITL=false\n"
            "HEXSWARM_TEMPERATURE=0.2\n"
            "HEXSWARM_MAX_STEPS=6\n",
            encoding="utf-8",
        )
        console.print(f"[green]Wrote {env_path}[/green]")

    if scope_path.exists() and not typer.confirm(f"{scope_path} already exists. Overwrite?", default=False):
        console.print(f"[yellow]Skipped writing {scope_path}.[/yellow]")
    else:
        allow_lines = "\n".join(f'  - "{a}"' for a in allow)
        scope_path.write_text(
            f'engagement_name: "{engagement_name}"\n'
            f"allow:\n{allow_lines}\n"
            "deny: []\n"
            f'max_risk_level: "{max_risk_level}"\n'
            f'authorized_by: "{authorized_by}"\n',
            encoding="utf-8",
        )
        console.print(f"[green]Wrote {scope_path}[/green]")

    console.print(Panel.fit(
        "[bold green]Setup complete.[/bold green] Try it:\n\n"
        f'[cyan]hexswarm run --goal "check for common vulnerabilities" '
        f'--target {allow[0]} --scope {scope_path}[/cyan]',
        border_style="green",
    ))


@app.command()
def doctor() -> None:
    """Check whether HexSwarm is actually ready to run: model reachable, tools installed."""
    settings = load_settings()
    all_ok = True

    console.print(Panel.fit("[bold]HexSwarm doctor[/bold]", border_style="cyan"))

    # --- Model check ---
    console.print(f"\n[bold]Model[/bold]: {settings.primary_model}")
    if settings.primary_model.startswith("ollama/"):
        base = os.getenv("OLLAMA_API_BASE", "http://localhost:11434").rstrip("/")
        try:
            urllib.request.urlopen(f"{base}/api/tags", timeout=2)  # nosec B310 - fixed localhost health check
            console.print(f"  [green]OK[/green] Ollama is reachable at {base}")
        except (urllib.error.URLError, OSError, TimeoutError):
            all_ok = False
            console.print(
                f"  [red]FAIL[/red] Can't reach Ollama at {base}. Run `ollama serve`, or pull the "
                f"model with `ollama pull {settings.primary_model.split('/', 1)[1]}` if you haven't."
            )
    else:
        provider = settings.primary_model.split("/", 1)[0]
        env_var = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}.get(provider)
        if env_var:
            if os.getenv(env_var):
                console.print(f"  [green]OK[/green] {env_var} is set")
            else:
                all_ok = False
                console.print(f"  [red]FAIL[/red] {env_var} is not set. Add it to your .env file.")
        else:
            console.print(
                f"  [yellow]SKIPPED[/yellow] Unrecognized provider '{provider}', check its "
                "required environment variable yourself."
            )

    # --- Tool availability summary ---
    tools = ToolRegistry.all()
    installed = sum(1 for t in tools.values() if t.local_only or t.is_available())
    console.print(f"\n[bold]Tools[/bold]: {installed}/{len(tools)} available (the rest run in simulate mode)")

    if all_ok:
        console.print("\n[bold green]Ready to run.[/bold green]")
    else:
        console.print("\n[bold red]Fix the items above before running against a real target.[/bold red]")
        raise typer.Exit(code=1)


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

    console.print(f"[bold]HexSwarm[/bold] running engagement '[cyan]{guard.engagement_name}[/cyan]' "
                  f"against '[yellow]{target}[/yellow]'...\n")

    with console.status("[bold cyan]Starting...[/bold cyan]", spinner="dots") as status:
        def on_progress(event: str, phase: str) -> None:
            if event == "start":
                status.update(f"[bold cyan]{phase}[/bold cyan] agent is working...")
            else:
                console.print(f"  [green]done[/green]  {phase}")

        orchestrator = Orchestrator(
            router=router,
            scope_guard=guard,
            findings=findings,
            human_in_the_loop=settings.human_in_the_loop,
            progress_callback=on_progress,
        )
        result = orchestrator.run(goal=goal, target=target)

    if "error" in result.phase_summaries:
        console.print(Panel(result.phase_summaries["error"], title="SCOPE ERROR", border_style="red"))
        raise typer.Exit(code=1)

    for phase, summary in result.phase_summaries.items():
        console.print(Panel(Markdown(summary), title=phase.upper(), border_style="magenta"))

    console.print(Panel(Markdown(result.report_markdown), title="FINAL REPORT", border_style="green"))

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

    console.print(f"[bold]HexSwarm CTF agent[/bold] analyzing '[yellow]{file}[/yellow]'...\n")
    with console.status("[bold cyan]Working...[/bold cyan]", spinner="dots"):
        summary = agent.run(goal=goal, target=str(file), guard=guard, findings=findings)

    console.print(Panel(Markdown(summary), title="RESULT", border_style="green"))


if __name__ == "__main__":
    app()
