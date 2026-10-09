from types import SimpleNamespace

import pytest

from hexswarm.llm.router import LLMMessage, LLMRouter


def fake_response(content="hello", tool_calls=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls or [])
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def test_complete_returns_plain_content():
    def fn(**kwargs):
        return fake_response(content="recon complete")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    resp = router.complete([LLMMessage(role="user", content="go")])
    assert resp.content == "recon complete"
    assert resp.model_used == "fake/model"
    assert resp.tool_calls == []


def test_complete_parses_tool_calls():
    tool_call = SimpleNamespace(
        id="call_1",
        function=SimpleNamespace(name="port_scan", arguments='{"target": "10.0.0.1"}'),
    )

    def fn(**kwargs):
        return fake_response(content="", tool_calls=[tool_call])

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)
    resp = router.complete([LLMMessage(role="user", content="go")], tools=[{"type": "function"}])
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].name == "port_scan"
    assert resp.tool_calls[0].arguments == {"target": "10.0.0.1"}


def test_falls_back_to_second_model_on_failure():
    calls = []

    def fn(**kwargs):
        calls.append(kwargs["model"])
        if kwargs["model"] == "primary/model":
            raise RuntimeError("provider down")
        return fake_response(content="from fallback")

    router = LLMRouter(
        primary_model="primary/model",
        fallback_models=["fallback/model"],
        completion_fn=fn,
        max_retries=1,
    )
    resp = router.complete([LLMMessage(role="user", content="go")])
    assert resp.content == "from fallback"
    assert resp.model_used == "fallback/model"
    assert calls == ["primary/model", "fallback/model"]


def test_raises_when_every_candidate_fails():
    def fn(**kwargs):
        raise RuntimeError("down")

    router = LLMRouter(primary_model="only/model", completion_fn=fn, max_retries=1)
    with pytest.raises(RuntimeError):
        router.complete([LLMMessage(role="user", content="go")])
