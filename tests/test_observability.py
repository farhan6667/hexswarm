import json
from types import SimpleNamespace

import pytest

from hexswarm.llm.router import LLMMessage, LLMRouter
from hexswarm.observability import Budget, BudgetExceeded, Telemetry, estimate_cost


def response_with_usage(content="ok", prompt_tokens=100, completion_tokens=50):
    message = SimpleNamespace(content=content, tool_calls=[])
    usage = SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


# --- Budget ---------------------------------------------------------------

def test_budget_unbounded_by_default():
    b = Budget()
    assert b.is_unbounded is True
    b.add(cost_usd=9999, tokens=10**9)
    b.check()  # must not raise


def test_budget_raises_when_cost_ceiling_crossed():
    b = Budget(max_cost_usd=0.10)
    b.add(cost_usd=0.11, tokens=0)
    with pytest.raises(BudgetExceeded):
        b.check()


def test_budget_raises_when_token_ceiling_crossed():
    b = Budget(max_tokens=100)
    b.add(cost_usd=0.0, tokens=101)
    with pytest.raises(BudgetExceeded):
        b.check()


def test_budget_allows_exactly_at_ceiling():
    b = Budget(max_cost_usd=0.10, max_tokens=100)
    b.add(cost_usd=0.10, tokens=100)
    b.check()  # at the limit, not over, must not raise


# --- Telemetry ------------------------------------------------------------

def test_telemetry_accumulates_totals():
    t = Telemetry(engagement_name="t")
    t.record_llm_call("m", prompt_tokens=100, completion_tokens=50, cost_usd=0.01, phase="recon")
    t.record_llm_call("m", prompt_tokens=200, completion_tokens=60, cost_usd=0.02, phase="scan")
    assert t.llm_calls == 2
    assert t.total_tokens == 410
    assert abs(t.total_cost_usd - 0.03) < 1e-9


def test_telemetry_records_tool_calls():
    t = Telemetry(engagement_name="t")
    t.record_tool_call("port_scan", "1.2.3.4", simulated=False, success=True, phase="recon")
    assert t.tool_calls == 1
    assert t.events[0].kind == "tool_call"
    assert t.events[0].detail["tool_name"] == "port_scan"


def test_telemetry_writes_jsonl_trace(tmp_path):
    trace = tmp_path / "trace.jsonl"
    t = Telemetry(engagement_name="t", trace_path=trace)
    t.record_llm_call("m", 10, 5, 0.001, phase="recon")
    t.record_tool_call("whois_lookup", "example.com", simulated=True, success=True, phase="recon")

    lines = trace.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["kind"] == "llm_call"
    assert first["detail"]["model"] == "m"
    second = json.loads(lines[1])
    assert second["kind"] == "tool_call"


# --- estimate_cost --------------------------------------------------------

def test_estimate_cost_reads_usage_and_handles_missing():
    with_usage = response_with_usage(prompt_tokens=100, completion_tokens=50)
    pt, ct, _cost = estimate_cost(with_usage)
    assert pt == 100
    assert ct == 50

    no_usage = SimpleNamespace(choices=[])
    pt, ct, cost = estimate_cost(no_usage)
    assert (pt, ct, cost) == (0, 0, 0.0)


# --- Router integration ---------------------------------------------------

def test_router_records_telemetry_per_call():
    def fn(**kwargs):
        return response_with_usage()

    telemetry = Telemetry(engagement_name="t")
    router = LLMRouter(primary_model="fake/model", completion_fn=fn, telemetry=telemetry, phase="recon")
    router.complete([LLMMessage(role="user", content="go")])
    assert telemetry.llm_calls == 1
    assert telemetry.total_tokens == 150
    assert telemetry.events[0].detail["phase"] == "recon"


def test_router_aborts_run_when_budget_exceeded():
    def fn(**kwargs):
        return response_with_usage(prompt_tokens=10_000, completion_tokens=10_000)

    budget = Budget(max_tokens=5_000)
    router = LLMRouter(primary_model="fake/model", completion_fn=fn, budget=budget)
    with pytest.raises(BudgetExceeded):
        router.complete([LLMMessage(role="user", content="go")])


def test_router_budget_exceeded_is_not_swallowed_by_fallback():
    # A budget hit must propagate immediately, not be treated as a provider failure
    # that silently rolls over to the next fallback model.
    calls = {"n": 0}

    def fn(**kwargs):
        calls["n"] += 1
        return response_with_usage(prompt_tokens=10_000, completion_tokens=0)

    budget = Budget(max_tokens=1_000)
    router = LLMRouter(
        primary_model="primary/model",
        fallback_models=["fallback/model"],
        completion_fn=fn,
        budget=budget,
    )
    with pytest.raises(BudgetExceeded):
        router.complete([LLMMessage(role="user", content="go")])
    assert calls["n"] == 1  # stopped at the first call, did not try the fallback


def test_router_unmetered_when_no_telemetry_or_budget():
    def fn(**kwargs):
        return response_with_usage()

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    resp = router.complete([LLMMessage(role="user", content="go")])
    assert resp.content == "ok"  # behaves exactly as before, nothing tracked
