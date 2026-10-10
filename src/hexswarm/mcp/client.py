"""Lets HexSwarm agents call tools from external MCP servers.

An operator who trusts a given MCP server (their own, or a published one like
PentestMCP) lists it in a small YAML config. Each of its tools shows up to
the agent as a `RemoteMCPTool`: a duck-typed stand-in for HexSwarm's own
`Tool` class that still goes through the exact same ScopeGuard check before
anything runs. The operator declares the risk tier and whether the target is
a real network host when they add the server, since HexSwarm has no way to
know what an arbitrary external tool actually does.

Every call opens a fresh stdio session to the configured server command and
closes it when done, rather than holding one open for the agent's whole
lifetime. Simpler and safer to reason about than a long-lived session: no
server-restart or reconnect logic needed, at the cost of one subprocess
startup per call.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel
from hexswarm.tools.base import ToolResult


@dataclass
class McpServerConfig:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    risk_level: ToolRiskLevel = ToolRiskLevel.INTRUSIVE
    requires_scope_check: bool = True
    category: str = "mcp-external"
    # A single server can expose a mix of tools, some that touch a real network
    # target and some that don't (HexSwarm's own MCP server is itself an example:
    # port_scan takes a host, decode_text takes an arbitrary string). Listing a
    # remote tool's name here turns off the host-scope check for that tool alone,
    # the same way a local Tool sets requires_scope_check=False on itself.
    non_scope_checked_tools: list[str] = field(default_factory=list)

    def to_server_params(self) -> StdioServerParameters:
        return StdioServerParameters(command=self.command, args=self.args, env=self.env)

    def requires_scope_check_for(self, remote_tool_name: str) -> bool:
        if remote_tool_name in self.non_scope_checked_tools:
            return False
        return self.requires_scope_check


def load_mcp_server_configs(path: str | Path) -> list[McpServerConfig]:
    """Loads external MCP server definitions from a YAML file.

    Expected shape:
        servers:
          - name: my-recon-server
            command: python
            args: ["-m", "my_mcp_server"]
            risk_level: active_recon     # defaults to intrusive
            requires_scope_check: true   # defaults to true
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"MCP server config not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    configs = []
    for entry in data.get("servers", []):
        configs.append(
            McpServerConfig(
                name=entry["name"],
                command=entry["command"],
                args=list(entry.get("args", [])),
                env=entry.get("env"),
                risk_level=ToolRiskLevel(entry.get("risk_level", "intrusive")),
                requires_scope_check=entry.get("requires_scope_check", True),
                category=entry.get("category", "mcp-external"),
                non_scope_checked_tools=list(entry.get("non_scope_checked_tools", [])),
            )
        )
    return configs


class RemoteMCPTool:
    """Duck-typed stand-in for `hexswarm.tools.base.Tool`, backed by one remote MCP tool."""

    local_only = False

    def __init__(
        self,
        server: McpServerConfig,
        remote_name: str,
        description: str,
        input_schema: dict[str, Any],
    ) -> None:
        self.server = server
        self.name = f"{server.name}.{remote_name}"
        self._remote_name = remote_name
        self.description = description or f"Remote MCP tool '{remote_name}' from '{server.name}'."
        self.parameters_schema = input_schema or {"type": "object", "properties": {}}
        self.risk_level = server.risk_level
        self.category = server.category
        self.requires_scope_check = server.requires_scope_check_for(remote_name)
        self.binary = f"mcp:{server.name}"

    def is_available(self) -> bool:
        return True

    async def _call_async(self, **kwargs: Any) -> str:
        params = self.server.to_server_params()
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(self._remote_name, arguments=kwargs)
            parts = []
            for item in result.content:
                text = getattr(item, "text", None)
                if text is not None:
                    parts.append(text)
            return "\n".join(parts) if parts else str(result.content)

    def run(self, guard: ScopeGuard, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target", "")
        if self.requires_scope_check:
            guard.authorize(target, self.risk_level)
        else:
            guard.check_risk(self.risk_level)

        command_str = f"mcp:{self.server.name}/{self._remote_name}({kwargs})"
        try:
            output = asyncio.run(self._call_async(**kwargs))
            return ToolResult(
                tool_name=self.name,
                target=target,
                command=command_str,
                simulated=False,
                success=True,
                output=output,
            )
        except Exception as exc:  # noqa: BLE001 - surface any transport/remote failure as a result
            return ToolResult(
                tool_name=self.name,
                target=target,
                command=command_str,
                simulated=False,
                success=False,
                output="",
                error=str(exc),
            )


class MCPToolClient:
    """Connects to one configured external MCP server and lists its tools."""

    def __init__(self, server: McpServerConfig) -> None:
        self.server = server

    async def _list_tools_async(self) -> list[RemoteMCPTool]:
        params = self.server.to_server_params()
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            return [
                RemoteMCPTool(
                    server=self.server,
                    remote_name=t.name,
                    description=t.description or "",
                    input_schema=t.inputSchema,
                )
                for t in result.tools
            ]

    def list_tools(self) -> list[RemoteMCPTool]:
        return asyncio.run(self._list_tools_async())


def load_all_remote_tools(config_path: str | Path) -> list[RemoteMCPTool]:
    """Connects to every server in a config file and returns their combined tool list.

    A server that fails to connect is skipped with its tools omitted rather than
    aborting the whole load, since one misconfigured external server shouldn't take
    down every other tool HexSwarm has.
    """
    tools: list[RemoteMCPTool] = []
    for server in load_mcp_server_configs(config_path):
        try:
            tools.extend(MCPToolClient(server).list_tools())
        except Exception:  # noqa: BLE001, S112 - a bad external server shouldn't break startup
            continue
    return tools
