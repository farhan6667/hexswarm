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
from hexswarm.agents.specialized import build_ai_security_agent, build_ctf_agent
from hexswarm.config import Settings, load_settings
from hexswarm.llm.router import LLMRouter
from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel
from hexswarm.tools.base import ToolRegistry
from hexswarm.tools.sandbox import configure_sandbox

app = typer.Typer(
    name="hexswarm",
    help="A swarm-of-agents framework for AI-driven offensive security research.",
    no_args_is_help=True,
)
console = Console()


def _apply_sandbox(settings: Settings) -> None:
    configure_sandbox(
        mode=settings.sandbox_mode,
        image=settings.sandbox_image,
        network=settings.sandbox_network,
    )

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
    _apply_sandbox(settings)
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


RISK_LEVEL_COLOR = {
    "read_only": "dim",
    "active_recon": "cyan",
    "intrusive": "yellow",
    "exploit": "bold red",
    "post_exploit": "bold red",
}


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
            status = "[cyan]n/a (pure Python)[/cyan]"
        elif tool.is_available():
            status = "[green]yes[/green]"
        else:
            status = "[yellow]no (simulate mode)[/yellow]"
        binary_label = "(local)" if tool.local_only else tool.binary
        risk_color = RISK_LEVEL_COLOR.get(tool.risk_level.value, "")
        risk_label = f"[{risk_color}]{tool.risk_level.value}[/{risk_color}]" if risk_color else tool.risk_level.value
        category_label = "[magenta]ctf[/magenta]" if tool.category == "ctf" else tool.category
        table.add_row(tool.name, category_label, risk_label, binary_label, status)
    console.print(table)


@app.command(name="playbooks")
def list_playbooks() -> None:
    """List the built-in engagement playbooks you can pass to `run --playbook`."""
    from hexswarm.playbooks import builtin_playbooks

    table = Table(title="HexSwarm built-in playbooks")
    table.add_column("Name")
    table.add_column("Phases")
    table.add_column("Max risk")
    table.add_column("Description")
    for pb in builtin_playbooks().values():
        table.add_row(pb.name, " -> ".join(pb.phases), pb.max_risk_level or "(scope default)", pb.description)
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
    target: str = typer.Option(..., "--target", "-t", help="Target host, IP, CIDR, or URL."),
    scope_file: Path = typer.Option(..., "--scope", "-s", help="Path to a scope YAML file."),
    goal: str = typer.Option(
        None, "--goal", "-g",
        help="High-level objective. Optional if --playbook is given (the playbook supplies one).",
    ),
    playbook: str = typer.Option(
        None, "--playbook", "-p",
        help="A built-in playbook name (recon-only, web-assessment, full-engagement) or a path to one.",
    ),
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
    max_cost: float = typer.Option(
        None, "--max-cost", help="Abort the engagement if LLM spend exceeds this many USD."
    ),
    max_tokens: int = typer.Option(
        None, "--max-tokens", help="Abort the engagement if total tokens exceed this count."
    ),
    trace_out: Path = typer.Option(
        None, "--trace-out", help="Optional JSONL path for the per-call cost/tool trace."
    ),
    sarif_out: Path = typer.Option(
        None, "--sarif-out", help="Optional SARIF path (for GitHub code scanning) of the findings."
    ),
    verify: bool = typer.Option(
        False, "--verify",
        help="Add a second-opinion verification pass that flags likely false positives before the report.",
    ),
) -> None:
    """Run the full recon -> scan -> exploit -> privesc -> report swarm against a target."""
    settings = load_settings()
    _apply_sandbox(settings)

    phase_order = None
    playbook_risk_cap = None
    if playbook is not None:
        from hexswarm.playbooks import resolve_playbook

        try:
            pb = resolve_playbook(playbook)
        except FileNotFoundError as exc:
            console.print(f"[red]Playbook error[/red]: {exc}")
            raise typer.Exit(code=1)
        goal = goal or pb.goal
        phase_order = pb.phases
        playbook_risk_cap = pb.max_risk_level
        console.print(f"[dim]Using playbook '{pb.name}': {pb.description}[/dim]")

    if not goal:
        console.print("[red]Error[/red]: provide --goal, or --playbook (which supplies one).")
        raise typer.Exit(code=1)

    try:
        guard = ScopeGuard.from_file(scope_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Scope error[/red]: {exc}")
        raise typer.Exit(code=1)

    # A playbook may only narrow the engagement's risk cap, never widen it: take the
    # lower of the scope file's cap and the playbook's.
    if playbook_risk_cap is not None:
        order = list(ToolRiskLevel)
        pb_level = ToolRiskLevel(playbook_risk_cap)
        if order.index(pb_level) < order.index(guard.max_risk_level):
            guard.max_risk_level = pb_level

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

    from hexswarm.observability import Budget, Telemetry

    telemetry = Telemetry(engagement_name=guard.engagement_name, trace_path=trace_out)
    budget = Budget(max_cost_usd=max_cost, max_tokens=max_tokens)

    router = LLMRouter(
        primary_model=model or settings.primary_model,
        fallback_models=settings.fallback_models,
        temperature=settings.temperature,
        telemetry=telemetry,
        budget=budget,
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
            phase_order=phase_order,
            verify=verify,
        )
        result = orchestrator.run(goal=goal, target=target)

    if "error" in result.phase_summaries:
        console.print(Panel(result.phase_summaries["error"], title="SCOPE ERROR", border_style="red"))
        raise typer.Exit(code=1)

    for phase, summary in result.phase_summaries.items():
        console.print(Panel(Markdown(summary), title=phase.upper(), border_style="magenta"))

    console.print(Panel(Markdown(result.report_markdown), title="FINAL REPORT", border_style="green"))

    if result.budget_exceeded:
        console.print("[yellow]Note: the engagement stopped early because a budget ceiling was reached.[/yellow]")

    report_out.write_text(result.report_markdown, encoding="utf-8")
    console.print(f"\n[green]Report written to {report_out}[/green]")
    console.print(f"[dim]Cost/usage: {telemetry.summary()}[/dim]")

    if sarif_out is not None:
        from hexswarm.reporting import findings_to_sarif

        sarif_out.write_text(findings_to_sarif(findings, target), encoding="utf-8")
        console.print(f"[green]SARIF written to {sarif_out}[/green]")


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
    _apply_sandbox(settings)
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


@app.command(name="ai-audit")
def ai_audit(
    goal: str = typer.Option(
        "Probe this endpoint for prompt-injection and system-prompt-leak weaknesses.",
        "--goal", "-g",
    ),
    target: str = typer.Option(..., "--target", "-t", help="Target LLM/chat HTTP endpoint URL."),
    scope_file: Path = typer.Option(..., "--scope", "-s", help="Path to a scope YAML file."),
    model: str = typer.Option(None, "--model", help="Override the primary LLM model string."),
) -> None:
    """Probe a target LLM/chat application's HTTP endpoint for prompt-injection weaknesses.

    The target is a real network endpoint, so a scope file is required, same as `run`.
    Flagged responses are heuristic hits for a human to review, not confirmed findings.
    """
    settings = load_settings()
    _apply_sandbox(settings)

    try:
        guard = ScopeGuard.from_file(scope_file)
        guard.check_target(target)
    except (FileNotFoundError, ValueError, ScopeViolation) as exc:
        console.print(f"[red]Scope error[/red]: {exc}")
        raise typer.Exit(code=1)

    router = LLMRouter(
        primary_model=model or settings.primary_model,
        fallback_models=settings.fallback_models,
        temperature=settings.temperature,
    )

    from hexswarm.memory.findings import FindingsStore

    findings = FindingsStore(engagement_name=guard.engagement_name)
    agent = build_ai_security_agent(router=router, model=model)

    console.print(f"[bold]HexSwarm AI Security agent[/bold] probing '[yellow]{target}[/yellow]'...\n")
    with console.status("[bold cyan]Working...[/bold cyan]", spinner="dots"):
        summary = agent.run(goal=goal, target=target, guard=guard, findings=findings)

    console.print(Panel(Markdown(summary), title="RESULT", border_style="green"))


@app.command(name="mcp-server")
def mcp_server(
    scope_file: Path = typer.Option(..., "--scope", "-s", help="Path to a scope YAML file."),
) -> None:
    """Expose every registered tool as an MCP server over stdio.

    Point any MCP client (Claude Desktop, Claude Code, etc.) at this command. Every tool
    call it makes is still checked against the given scope file before it runs, there is no
    separate, looser code path for the MCP transport.
    """
    from hexswarm.mcp.server import build_server

    _apply_sandbox(load_settings())

    try:
        guard = ScopeGuard.from_file(scope_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Scope error[/red]: {exc}")
        raise typer.Exit(code=1)

    server = build_server(guard)
    server.run()


@app.command()
def bench(
    manifest: Path = typer.Option(
        Path("examples/benchmarks/manifest.yaml"), "--manifest", "-m",
        help="Path to a benchmark manifest.yaml.",
    ),
    model: str = typer.Option(None, "--model", help="Override the primary LLM model string."),
    report_out: Path = typer.Option(
        Path("BENCHMARK_RESULTS.md"), "--report-out", help="Where to write the Markdown report."
    ),
) -> None:
    """Run the CTF agent against HexSwarm's own small local benchmark suite.

    One honest, reproducible number per model/version instead of a vibe: anyone can clone
    the repo and run this same command against the same challenges.
    """
    from hexswarm.bench import load_challenges, run_benchmark
    from hexswarm.safety.guard import ToolRiskLevel

    settings = load_settings()
    _apply_sandbox(settings)

    try:
        challenges = load_challenges(manifest)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    router = LLMRouter(
        primary_model=model or settings.primary_model,
        fallback_models=settings.fallback_models,
        temperature=settings.temperature,
    )

    def agent_factory():
        return build_ctf_agent(router=router, model=model)

    def guard_factory():
        return ScopeGuard(
            engagement_name="bench", allow=["local-file-analysis"], max_risk_level=ToolRiskLevel.READ_ONLY
        )

    console.print(f"[bold]Running {len(challenges)} benchmark challenges against "
                  f"'{model or settings.primary_model}'...[/bold]\n")
    with console.status("[bold cyan]Working...[/bold cyan]", spinner="dots"):
        report = run_benchmark(challenges, agent_factory, guard_factory)

    for result in report.results:
        mark = "[green]PASS[/green]" if result.solved else "[red]FAIL[/red]"
        console.print(f"  {mark}  {result.challenge_id}")

    console.print(f"\n[bold]{report.solved_count}/{report.total_count} solved[/bold]")
    report_out.write_text(report.to_markdown(), encoding="utf-8")
    console.print(f"[green]Report written to {report_out}[/green]")


@app.command()
def lab(
    action: str = typer.Argument(..., help="One of: list, up, down."),
    name: str = typer.Argument(None, help="Lab name (required for up/down), e.g. juice-shop."),
) -> None:
    """Manage bundled vulnerable labs: disposable localhost targets for real end-to-end testing.

    `hexswarm lab list` shows what's available; `hexswarm lab up juice-shop` starts one, and
    `hexswarm lab down juice-shop` tears it down. Each lab ships with a matching scope file
    (examples/labs/<name>.scope.yaml) so you can point a run at it immediately.
    """
    from hexswarm.labs import available_labs, docker_available, run_lab_action, scope_file_for

    labs = available_labs()

    if action == "list":
        table = Table(title="HexSwarm bundled labs")
        table.add_column("Name")
        table.add_column("Scope file")
        for lab_name in labs:
            scope = scope_file_for(lab_name)
            table.add_row(lab_name, str(scope) if scope else "(none)")
        console.print(table)
        return

    if action not in ("up", "down"):
        console.print(f"[red]Unknown action '{action}'[/red] (expected list, up, or down).")
        raise typer.Exit(code=1)

    if name is None:
        console.print(f"[red]A lab name is required for '{action}'[/red] (see `hexswarm lab list`).")
        raise typer.Exit(code=1)

    if not docker_available():
        console.print("[red]Docker not found[/red]. Labs need Docker + the compose plugin installed.")
        raise typer.Exit(code=1)

    try:
        console.print(f"[bold]Lab {action}[/bold]: {name}...")
        result = run_lab_action(name, action)
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    if result.returncode != 0:
        console.print(f"[red]docker compose {action} failed:[/red]\n{result.stderr}")
        raise typer.Exit(code=1)

    console.print(f"[green]Lab '{name}' {action} complete.[/green]")
    if action == "up":
        scope = scope_file_for(name)
        if scope:
            console.print(
                f"[dim]Try: hexswarm run --playbook web-assessment --target http://localhost:3000 "
                f"--scope {scope} --yes[/dim]"
            )


if __name__ == "__main__":
    app()
