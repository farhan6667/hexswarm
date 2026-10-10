import asyncio

from hexswarm.mcp.server import build_server
from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel
from hexswarm.tools.base import ToolRegistry


def make_guard(allow=None, max_risk=ToolRiskLevel.POST_EXPLOIT):
    return ScopeGuard(engagement_name="t", allow=allow or ["scanme.nmap.org"], max_risk_level=max_risk)


def test_build_server_registers_every_tool():
    server = build_server(make_guard())
    registered = server._tool_manager.list_tools()
    assert len(registered) == len(ToolRegistry.all())
    names = {t.name for t in registered}
    assert "port_scan" in names
    assert "decode_text" in names


def test_schema_marks_required_vs_optional_params_correctly():
    server = build_server(make_guard())
    tool = server._tool_manager.get_tool("port_scan")
    schema = tool.parameters
    assert schema["required"] == ["target"]
    assert "ports" in schema["properties"]
    assert schema["properties"]["ports"]["default"] == ""


def test_calling_a_tool_through_the_server_runs_it_for_real(monkeypatch):
    server = build_server(make_guard())
    tool = server._tool_manager.get_tool("whois_lookup")
    # whois almost certainly isn't installed in CI, so this exercises the simulate path,
    # proving the call actually reached Tool.run() through the MCP wrapper.
    result = asyncio.run(tool.run({"target": "scanme.nmap.org"}))
    assert "SIMULATED" in result or "succeeded" in result


def test_scope_violation_is_returned_as_text_not_raised():
    server = build_server(make_guard(allow=["example.com"]))
    tool = server._tool_manager.get_tool("port_scan")
    result = asyncio.run(tool.run({"target": "totally-out-of-scope.tld"}))
    assert "Scope violation" in result


def test_requires_scope_check_false_tool_skips_host_matching():
    # exploit_search's target is a search string, not a host; a narrow allow list that
    # could never match a free-text string must still not block it.
    server = build_server(make_guard(allow=["10.10.10.0/24"]))
    tool = server._tool_manager.get_tool("exploit_search")
    result = asyncio.run(tool.run({"target": "vsftpd 2.3.4"}))
    assert "Scope violation" not in result
