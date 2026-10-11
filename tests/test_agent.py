from types import SimpleNamespace

from hexswarm.agents.base import Agent, AgentConfig
from hexswarm.llm.router import LLMRouter
from hexswarm.memory.findings import FindingsStore
from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel
from hexswarm.tools.base import ToolRegistry


def fake_response(content="", tool_calls=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls or [])
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def make_guard():
    return ScopeGuard(
        engagement_name="t", allow=["example.com"], max_risk_level=ToolRiskLevel.POST_EXPLOIT
    )


def test_agent_calls_tool_then_returns_summary():
    call_log = []

    def fn(**kwargs):
        call_log.append(kwargs)
        if len(call_log) == 1:
            tc = SimpleNamespace(
                id="c1",
                function=SimpleNamespace(name="whois_lookup", arguments='{"target": "example.com"}'),
            )
            return fake_response(tool_calls=[tc])
        return fake_response(content="Recon complete: WHOIS data gathered for example.com.")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    tool = ToolRegistry.get("whois_lookup")
    config = AgentConfig(name="recon_agent", phase="recon", system_prompt="be a recon agent", tools=[tool])
    agent = Agent(config=config, router=router)

    findings = FindingsStore(engagement_name="t")
    summary = agent.run(goal="map the target", target="example.com", guard=make_guard(), findings=findings)

    assert "Recon complete" in summary
    assert len(findings.all()) == 1
    assert findings.all()[0].tool_name == "whois_lookup"
    assert len(call_log) == 2


def test_agent_respects_hitl_rejection():
    tc = SimpleNamespace(
        id="c1",
        function=SimpleNamespace(name="whois_lookup", arguments='{"target": "example.com"}'),
    )
    calls = {"n": 0}

    def fn(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return fake_response(tool_calls=[tc])
        return fake_response(content="done")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    tool = ToolRegistry.get("whois_lookup")
    config = AgentConfig(name="recon_agent", phase="recon", system_prompt="x", tools=[tool])
    agent = Agent(
        config=config,
        router=router,
        human_in_the_loop=True,
        confirm_fn=lambda name, args: False,
    )

    findings = FindingsStore(engagement_name="t")
    summary = agent.run(goal="g", target="example.com", guard=make_guard(), findings=findings)

    assert summary == "done"
    assert len(findings.all()) == 0  # tool call was skipped, nothing recorded


def test_agent_handles_scope_violation_gracefully():
    tc = SimpleNamespace(
        id="c1",
        function=SimpleNamespace(name="whois_lookup", arguments='{"target": "out-of-scope.com"}'),
    )
    calls = {"n": 0}

    def fn(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return fake_response(tool_calls=[tc])
        return fake_response(content="handled")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    tool = ToolRegistry.get("whois_lookup")
    config = AgentConfig(name="recon_agent", phase="recon", system_prompt="x", tools=[tool])
    agent = Agent(config=config, router=router)

    findings = FindingsStore(engagement_name="t")
    summary = agent.run(goal="g", target="example.com", guard=make_guard(), findings=findings)

    assert summary == "handled"
    assert len(findings.all()) == 0


def test_threshold_hitl_auto_runs_low_risk_tools():
    # confirm_from_risk=EXPLOIT means recon/read-only runs without asking.
    from hexswarm.agents.base import Agent, AgentConfig
    from hexswarm.safety.guard import ToolRiskLevel
    from hexswarm.tools.base import ToolRegistry

    tc = SimpleNamespace(id="c1", function=SimpleNamespace(name="whois_lookup", arguments='{"target": "example.com"}'))
    calls = {"n": 0}

    def fn(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return fake_response(tool_calls=[tc])
        return fake_response(content="done")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    tool = ToolRegistry.get("whois_lookup")  # read_only
    config = AgentConfig(name="recon_agent", phase="recon", system_prompt="x", tools=[tool])
    confirm_calls = {"n": 0}
    agent = Agent(
        config=config, router=router,
        confirm_from_risk=ToolRiskLevel.EXPLOIT,
        confirm_fn=lambda name, args: (confirm_calls.__setitem__("n", confirm_calls["n"] + 1), True)[1],
    )

    findings = FindingsStore(engagement_name="t")
    agent.run(goal="g", target="example.com", guard=make_guard(), findings=findings)

    assert confirm_calls["n"] == 0  # read_only is below EXPLOIT, never asked
    assert len(findings.all()) == 1  # and it ran


def test_threshold_hitl_pauses_at_or_above_tier():
    from hexswarm.agents.base import Agent, AgentConfig
    from hexswarm.safety.guard import ToolRiskLevel
    from hexswarm.tools.base import ToolRegistry

    tc = SimpleNamespace(id="c1", function=SimpleNamespace(name="metasploit_module_run",
                         arguments='{"target": "10.10.10.5", "module": "exploit/x"}'))
    calls = {"n": 0}

    def fn(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return fake_response(tool_calls=[tc])
        return fake_response(content="done")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    tool = ToolRegistry.get("metasploit_module_run")  # exploit tier
    config = AgentConfig(name="exploit_agent", phase="exploit", system_prompt="x", tools=[tool])
    confirm_calls = {"n": 0}

    def deny(name, args):
        confirm_calls["n"] += 1
        return False  # operator declines

    agent = Agent(config=config, router=router, confirm_from_risk=ToolRiskLevel.EXPLOIT, confirm_fn=deny)
    guard = ScopeGuard(engagement_name="t", allow=["10.10.10.0/24"], max_risk_level=ToolRiskLevel.POST_EXPLOIT)
    findings = FindingsStore(engagement_name="t")
    agent.run(goal="g", target="10.10.10.5", guard=guard, findings=findings)

    assert confirm_calls["n"] == 1  # exploit tier triggered a confirmation
    assert len(findings.all()) == 0  # declined, so nothing ran
