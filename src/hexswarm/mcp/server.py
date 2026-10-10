"""Exposes HexSwarm's tool registry as an MCP server.

This lets any MCP client (Claude Desktop, Claude Code, Kali's native MCP
workflow, or anything else that speaks the protocol) call HexSwarm's tools
directly, the same scope-gated way the built-in agents do. The scope file is
fixed at server startup, not negotiable per call: an MCP client can only ever
touch what that one scope file authorizes for the lifetime of the server
process.

FastMCP builds each tool's JSON schema by inspecting a Python function's
*signature*, not from an arbitrary schema dict. HexSwarm's tools already
carry a hand-written JSON schema (`parameters_schema`) built for OpenAI-style
function calling, and every property in every tool happens to be a plain
string, so rather than hand-writing N near-identical wrapper functions, each
tool gets one real Python function with a synthetic `inspect.Signature`
attached (`__signature__`). FastMCP introspects that signature to build the
schema; the function body itself still just takes `**kwargs` and forwards to
the tool's own `run()`. The two are independent: the fake signature only
feeds the introspector, the real call always goes through `**kwargs`.
"""
from __future__ import annotations

import inspect
from typing import Any

from mcp.server.fastmcp import FastMCP

from hexswarm.safety.guard import ScopeGuard, ScopeViolation
from hexswarm.tools.base import ToolRegistry


def _make_wrapper(tool_name: str, guard: ScopeGuard):
    tool = ToolRegistry.get(tool_name)
    schema = tool.parameters_schema
    properties: dict[str, Any] = schema.get("properties", {})
    required = set(schema.get("required", []))

    def impl(**kwargs: Any) -> str:
        try:
            result = tool.run(guard, **kwargs)
        except ScopeViolation as exc:
            return f"Scope violation, tool not executed: {exc}"
        except Exception as exc:  # noqa: BLE001 - surface adapter failures to the MCP client
            return f"Tool '{tool_name}' raised an error: {exc}"
        prefix = "[SIMULATED] " if result.simulated else ""
        status = "succeeded" if result.success else "failed"
        return f"{prefix}{status}\nOutput:\n{result.output}\nError:\n{result.error}"

    parameters = [
        inspect.Parameter(
            name,
            inspect.Parameter.KEYWORD_ONLY,
            annotation=str,
            default=inspect.Parameter.empty if name in required else "",
        )
        for name in properties
    ]
    impl.__signature__ = inspect.Signature(parameters=parameters)  # type: ignore[attr-defined]
    impl.__name__ = tool_name
    impl.__doc__ = tool.description
    return impl


def build_server(guard: ScopeGuard, name: str = "hexswarm") -> FastMCP:
    """Builds a FastMCP server exposing every registered HexSwarm tool.

    Every call still goes through the same ScopeGuard as the CLI/agent path:
    this is a different transport for the same gated tool registry, not a
    bypass of it.
    """
    server = FastMCP(
        name=name,
        instructions=(
            "HexSwarm offensive-security and CTF tools, gated by the scope file "
            f"'{guard.engagement_name}' this server was started with. A tool call "
            "targeting something outside that scope is rejected before anything runs."
        ),
    )
    for tool_name in ToolRegistry.all():
        wrapper = _make_wrapper(tool_name, guard)
        tool = ToolRegistry.get(tool_name)
        server.add_tool(wrapper, name=tool_name, description=tool.description)
    return server
