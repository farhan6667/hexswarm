from types import SimpleNamespace

from hexswarm.agents.orchestrator import Orchestrator
from hexswarm.agents.specialized import build_verify_agent
from hexswarm.llm.router import LLMRouter
from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel


def fake_response(content):
    message = SimpleNamespace(content=content, tool_calls=[])
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def make_guard():
    return ScopeGuard(engagement_name="demo", allow=["example.com"], max_risk_level=ToolRiskLevel.POST_EXPLOIT)


def test_verify_agent_has_no_tools():
    router = LLMRouter(primary_model="fake/model", completion_fn=lambda **k: fake_response("x"))
    agent = build_verify_agent(router=router)
    assert agent.config.tools == []
    assert agent.config.phase == "verify"


def test_orchestrator_runs_verify_phase_when_enabled():
    def fn(**kwargs):
        messages = kwargs["messages"]
        system = next(m["content"] for m in messages if m["role"] == "system")
        if "Verify agent" in system:
            return fake_response("port_scan on example.com: LIKELY TRUE POSITIVE, real open port. 1 real, 0 shaky.")
        return fake_response("phase done")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    orchestrator = Orchestrator(
        router=router, scope_guard=make_guard(), phase_order=["recon"], verify=True
    )
    result = orchestrator.run(goal="assess", target="example.com")

    assert "verify" in result.phase_summaries
    assert "LIKELY TRUE POSITIVE" in result.phase_summaries["verify"]


def test_orchestrator_skips_verify_phase_by_default():
    router = LLMRouter(primary_model="fake/model", completion_fn=lambda **k: fake_response("ok"))
    orchestrator = Orchestrator(router=router, scope_guard=make_guard(), phase_order=["recon"])
    result = orchestrator.run(goal="assess", target="example.com")
    assert "verify" not in result.phase_summaries


def test_verify_phase_ordering_is_after_actions_before_report():
    seen_phases = []

    def fn(**kwargs):
        system = next(m["content"] for m in kwargs["messages"] if m["role"] == "system")
        if "Recon agent" in system:
            seen_phases.append("recon")
        elif "Verify agent" in system:
            seen_phases.append("verify")
        elif "Report agent" in system:
            seen_phases.append("report")
        return fake_response("done")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    orchestrator = Orchestrator(
        router=router, scope_guard=make_guard(), phase_order=["recon"], verify=True
    )
    orchestrator.run(goal="assess", target="example.com")
    assert seen_phases == ["recon", "verify", "report"]
