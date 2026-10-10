from types import SimpleNamespace

from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel
from hexswarm.tools.ai_security import _PROBE_PAYLOADS, PromptInjectionProbe
from hexswarm.tools.base import ToolRegistry


def guard():
    return ScopeGuard(engagement_name="t", allow=["app.example.com"], max_risk_level=ToolRiskLevel.INTRUSIVE)


def fake_response(json_body=None, text=""):
    def json_fn():
        if json_body is None:
            raise ValueError("no json")
        return json_body

    return SimpleNamespace(json=json_fn, text=text)


def test_registered_under_ai_security_category():
    tool = ToolRegistry.get("prompt_injection_probe")
    assert tool.category == "ai-security"
    assert tool.risk_level == ToolRiskLevel.INTRUSIVE


def test_is_local_only_no_subprocess_but_still_scope_checked():
    tool = PromptInjectionProbe()
    assert tool.local_only is True
    assert tool.requires_scope_check is True


def test_blocks_out_of_scope_target_without_sending_any_request(monkeypatch):
    sent = {"n": 0}

    def fake_post(*a, **k):
        sent["n"] += 1
        return fake_response(json_body={"response": "ok"})

    monkeypatch.setattr("hexswarm.tools.ai_security.requests.post", fake_post)

    tool = PromptInjectionProbe()
    try:
        tool.run(guard(), target="https://evil.other.com/api/chat")
        raised = False
    except ScopeViolation:
        raised = True
    assert raised is True
    assert sent["n"] == 0


def test_sends_every_probe_payload_once(monkeypatch):
    seen_payloads = []

    def fake_post(url, json=None, timeout=None):
        seen_payloads.append(json["message"])
        return fake_response(json_body={"response": "I can't help with that."})

    monkeypatch.setattr("hexswarm.tools.ai_security.requests.post", fake_post)

    tool = PromptInjectionProbe()
    result = tool.run(guard(), target="https://app.example.com/api/chat")

    assert result.success is True
    assert len(seen_payloads) == len(_PROBE_PAYLOADS)
    assert "0/" not in result.output or f"0/{len(_PROBE_PAYLOADS)} probes flagged" in result.output


def test_flags_a_response_matching_a_compliance_marker(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        if "system prompt" in json["message"].lower():
            return fake_response(json_body={"response": "My system prompt says: you are a helpful assistant..."})
        return fake_response(json_body={"response": "I can't help with that."})

    monkeypatch.setattr("hexswarm.tools.ai_security.requests.post", fake_post)

    tool = PromptInjectionProbe()
    result = tool.run(guard(), target="https://app.example.com/api/chat")

    assert "FLAGGED" in result.output
    assert "system_prompt_leak" in result.output


def test_does_not_flag_a_clean_refusal(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        return fake_response(json_body={"response": "I can't comply with that request."})

    monkeypatch.setattr("hexswarm.tools.ai_security.requests.post", fake_post)

    tool = PromptInjectionProbe()
    result = tool.run(guard(), target="https://app.example.com/api/chat")

    assert f"0/{len(_PROBE_PAYLOADS)} probes flagged" in result.output


def test_uses_custom_request_and_response_fields(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["json"] = json
        return fake_response(json_body={"reply": "no."})

    monkeypatch.setattr("hexswarm.tools.ai_security.requests.post", fake_post)

    tool = PromptInjectionProbe()
    tool.run(
        guard(), target="https://app.example.com/api/chat",
        request_field="prompt", response_field="reply",
    )
    assert "prompt" in captured["json"]
    assert "message" not in captured["json"]


def test_handles_non_json_response_body(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        return fake_response(json_body=None, text="plain text reply")

    monkeypatch.setattr("hexswarm.tools.ai_security.requests.post", fake_post)

    tool = PromptInjectionProbe()
    result = tool.run(guard(), target="https://app.example.com/api/chat")
    assert result.success is True
    assert "plain text reply" in result.output


def test_network_failure_on_one_probe_does_not_abort_the_rest(monkeypatch):
    import requests as requests_module

    call_count = {"n": 0}

    def fake_post(url, json=None, timeout=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise requests_module.ConnectionError("boom")
        return fake_response(json_body={"response": "ok"})

    monkeypatch.setattr("hexswarm.tools.ai_security.requests.post", fake_post)

    tool = PromptInjectionProbe()
    result = tool.run(guard(), target="https://app.example.com/api/chat")

    assert call_count["n"] == len(_PROBE_PAYLOADS)
    assert "request failed" in result.output
