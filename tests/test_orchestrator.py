from types import SimpleNamespace

from hexswarm.agents.orchestrator import Orchestrator
from hexswarm.llm.router import LLMRouter
from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel


def fake_response(content):
    message = SimpleNamespace(content=content, tool_calls=[])
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def make_guard(max_risk=ToolRiskLevel.POST_EXPLOIT):
    return ScopeGuard(engagement_name="demo", allow=["example.com"], max_risk_level=max_risk)


def test_orchestrator_runs_all_phases_in_order():
    def fn(**kwargs):
        # every agent immediately hands off with no tool calls
        return fake_response("phase done")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    orchestrator = Orchestrator(router=router, scope_guard=make_guard())

    result = orchestrator.run(goal="assess example.com", target="example.com")

    assert list(result.phase_summaries.keys()) == ["recon", "scan", "exploit", "privesc"]
    assert all(v == "phase done" for v in result.phase_summaries.values())
    assert result.report_markdown == "phase done"


def test_orchestrator_aborts_on_out_of_scope_target():
    def fn(**kwargs):
        return fake_response("should not be reached")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    orchestrator = Orchestrator(router=router, scope_guard=make_guard())

    result = orchestrator.run(goal="assess", target="totally-unauthorized.com")

    assert "error" in result.phase_summaries
    assert "Engagement aborted" in result.report_markdown


def test_orchestrator_respects_custom_phase_order():
    def fn(**kwargs):
        return fake_response("ok")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    orchestrator = Orchestrator(
        router=router, scope_guard=make_guard(), phase_order=["recon", "scan"]
    )
    result = orchestrator.run(goal="assess", target="example.com")
    assert list(result.phase_summaries.keys()) == ["recon", "scan"]


def test_orchestrator_fires_progress_callback_for_every_phase_and_report():
    def fn(**kwargs):
        return fake_response("ok")

    events: list[tuple[str, str]] = []
    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    orchestrator = Orchestrator(
        router=router,
        scope_guard=make_guard(),
        phase_order=["recon", "scan"],
        progress_callback=lambda event, phase: events.append((event, phase)),
    )
    orchestrator.run(goal="assess", target="example.com")

    assert events == [
        ("start", "recon"), ("done", "recon"),
        ("start", "scan"), ("done", "scan"),
        ("start", "report"), ("done", "report"),
    ]


def test_orchestrator_stops_cleanly_when_budget_exceeded():
    from hexswarm.observability import Budget

    def fn(**kwargs):
        message = SimpleNamespace(content="ok", tool_calls=[])
        usage = SimpleNamespace(prompt_tokens=10_000, completion_tokens=0)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)

    budget = Budget(max_tokens=1_000)
    router = LLMRouter(primary_model="fake/model", completion_fn=fn, budget=budget)
    orchestrator = Orchestrator(router=router, scope_guard=make_guard())

    result = orchestrator.run(goal="assess", target="example.com")

    assert result.budget_exceeded is True
    # The first phase trips the budget; later phases must never run.
    assert "recon" in result.phase_summaries
    assert "scan" not in result.phase_summaries
    assert "budget exceeded" in result.report_markdown.lower()


def test_orchestrator_never_fires_progress_callback_on_scope_abort():
    def fn(**kwargs):
        return fake_response("should not run")

    events: list[tuple[str, str]] = []
    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    orchestrator = Orchestrator(
        router=router,
        scope_guard=make_guard(),
        progress_callback=lambda event, phase: events.append((event, phase)),
    )
    orchestrator.run(goal="assess", target="totally-unauthorized.com")
    assert events == []
