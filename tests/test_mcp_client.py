import pytest

from hexswarm.mcp.client import McpServerConfig, RemoteMCPTool, load_mcp_server_configs
from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel


def test_remote_tool_exposes_openai_schema_like_a_builtin():
    # The agent/registry treat a RemoteMCPTool as a Tool, so it must expose the same
    # to_openai_schema() the built-ins do, or building tool schemas for the LLM crashes.
    server = McpServerConfig(name="svc", command="python")
    tool = RemoteMCPTool(
        server=server,
        remote_name="demo_scan",
        description="scan a thing",
        input_schema={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
    )
    schema = tool.to_openai_schema()
    assert schema["type"] == "function"
    assert schema["function"]["name"] == "svc.demo_scan"
    assert schema["function"]["parameters"]["required"] == ["target"]


def test_requires_scope_check_for_default_applies_to_every_tool():
    server = McpServerConfig(name="svc", command="python", requires_scope_check=True)
    assert server.requires_scope_check_for("some_tool") is True


def test_requires_scope_check_for_honors_per_tool_exception_list():
    server = McpServerConfig(
        name="svc",
        command="python",
        requires_scope_check=True,
        non_scope_checked_tools=["decode_text", "file_identify"],
    )
    assert server.requires_scope_check_for("decode_text") is False
    assert server.requires_scope_check_for("port_scan") is True


def test_load_mcp_server_configs_parses_yaml(tmp_path):
    config_file = tmp_path / "mcp_servers.yaml"
    config_file.write_text(
        """
servers:
  - name: local-hexswarm
    command: hexswarm
    args: ["mcp-server", "--scope", "scope.yaml"]
    risk_level: post_exploit
    non_scope_checked_tools: ["decode_text"]
""",
        encoding="utf-8",
    )
    configs = load_mcp_server_configs(config_file)
    assert len(configs) == 1
    assert configs[0].name == "local-hexswarm"
    assert configs[0].args == ["mcp-server", "--scope", "scope.yaml"]
    assert configs[0].risk_level == ToolRiskLevel.POST_EXPLOIT
    assert configs[0].non_scope_checked_tools == ["decode_text"]


def test_load_mcp_server_configs_defaults(tmp_path):
    config_file = tmp_path / "mcp_servers.yaml"
    config_file.write_text("servers:\n  - name: s\n    command: c\n", encoding="utf-8")
    configs = load_mcp_server_configs(config_file)
    assert configs[0].risk_level == ToolRiskLevel.INTRUSIVE
    assert configs[0].requires_scope_check is True
    assert configs[0].category == "mcp-external"


def test_load_mcp_server_configs_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_mcp_server_configs(tmp_path / "nope.yaml")


def test_remote_tool_blocks_out_of_scope_target_without_calling_remote(monkeypatch):
    server = McpServerConfig(name="svc", command="python", risk_level=ToolRiskLevel.INTRUSIVE)
    tool = RemoteMCPTool(
        server=server,
        remote_name="some_scan",
        description="d",
        input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
    )

    called = {"n": 0}

    async def fake_call(**kwargs):
        called["n"] += 1
        return "should not run"

    monkeypatch.setattr(tool, "_call_async", fake_call)

    guard = ScopeGuard(engagement_name="t", allow=["example.com"], max_risk_level=ToolRiskLevel.POST_EXPLOIT)
    with pytest.raises(ScopeViolation):
        tool.run(guard, target="out-of-scope.tld")
    assert called["n"] == 0


def test_remote_tool_runs_for_real_when_in_scope(monkeypatch):
    server = McpServerConfig(name="svc", command="python", risk_level=ToolRiskLevel.INTRUSIVE)
    tool = RemoteMCPTool(
        server=server,
        remote_name="some_scan",
        description="d",
        input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
    )

    async def fake_call(**kwargs):
        return f"scanned {kwargs['target']}"

    monkeypatch.setattr(tool, "_call_async", fake_call)

    guard = ScopeGuard(engagement_name="t", allow=["example.com"], max_risk_level=ToolRiskLevel.POST_EXPLOIT)
    result = tool.run(guard, target="example.com")
    assert result.success is True
    assert result.output == "scanned example.com"


def test_remote_tool_skips_scope_check_when_configured(monkeypatch):
    server = McpServerConfig(
        name="svc", command="python", non_scope_checked_tools=["decode_text"],
    )
    tool = RemoteMCPTool(
        server=server,
        remote_name="decode_text",
        description="d",
        input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
    )

    async def fake_call(**kwargs):
        return "decoded!"

    monkeypatch.setattr(tool, "_call_async", fake_call)

    # Deliberately narrow allow list that could never match an arbitrary string.
    guard = ScopeGuard(engagement_name="t", allow=["example.com"], max_risk_level=ToolRiskLevel.POST_EXPLOIT)
    result = tool.run(guard, target="c29tZSBzdHJpbmc=")
    assert result.success is True
    assert result.output == "decoded!"


def test_remote_tool_surfaces_transport_errors_as_failed_result(monkeypatch):
    server = McpServerConfig(name="svc", command="python")
    tool = RemoteMCPTool(
        server=server,
        remote_name="some_scan",
        description="d",
        input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
    )

    async def fake_call(**kwargs):
        raise ConnectionError("remote server unreachable")

    monkeypatch.setattr(tool, "_call_async", fake_call)

    guard = ScopeGuard(engagement_name="t", allow=["example.com"], max_risk_level=ToolRiskLevel.POST_EXPLOIT)
    result = tool.run(guard, target="example.com")
    assert result.success is False
    assert "remote server unreachable" in result.error
