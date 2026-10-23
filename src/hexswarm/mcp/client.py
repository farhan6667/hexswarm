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

from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel
from hexswarm.tools.base import ToolResult

# A remote tool's actual host-naming argument isn't always called "target": an MCP server
# someone else wrote might call it "url" or "host" instead. Checking only "target" meant any
# such tool's real network destination never went through the scope guard at all (it still
# got authorized, just on an empty string standing in for it). Every one of these is checked,
# in order, and the first one present with a non-empty value is what gets scope-checked.
DEFAULT_HOST_FIELDS: tuple[str, ...] = ("target", "url", "host", "hostname")


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
    # Maps a remote tool's name to the single kwarg name that holds its host, when that isn't
    # one of DEFAULT_HOST_FIELDS or when a tool happens to have more than one of them and the
    # operator knows which one is real (e.g. both "host" and "url" present, only "url" is
    # actually dialed). Optional: most tools don't need an entry here.
    host_fields: dict[str, str] = field(default_factory=dict)

    def to_server_params(self) -> StdioServerParameters:
        return StdioServerParameters(command=self.command, args=self.args, env=self.env)

    def requires_scope_check_for(self, remote_tool_name: str) -> bool:
        if remote_tool_name in self.non_scope_checked_tools:
            return False
        return self.requires_scope_check

    def host_field_for(self, remote_tool_name: str) -> str | None:
        return self.host_fields.get(remote_tool_name)


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
                host_fields=dict(entry.get("host_fields", {})),
            )
        )
    return configs


class RemoteMCPTool:
    """Duck-typed stand-in for `hexswarm.tools.base.Tool`, backed by one remote MCP tool.

    Not a Tool subclass on purpose: Tool's fields are ClassVars (shared per subclass), but
    every RemoteMCPTool needs its own per-instance name/risk/category/schema, so it
    implements the same interface structurally instead (name, description, risk_level,
    category, requires_scope_check, is_available, run, to_openai_schema). Callers that store
    it alongside real Tools cast it (see cli register site).
    """

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

    def to_openai_schema(self) -> dict[str, Any]:
        """OpenAI-style function schema, same shape a built-in Tool produces.

        A RemoteMCPTool is duck-typed as a Tool so the agents and registry can treat it
        identically; this is the method the agent calls to hand the tool to the LLM, so it
        has to exist here too, built from the remote tool's own input schema.
        """
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema,
            },
        }

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

    def _extract_host_value(self, kwargs: dict[str, Any]) -> str:
        override = self.server.host_field_for(self._remote_name)
        if override is not None:
            value = kwargs.get(override, "")
            return value if isinstance(value, str) else ""
        for field_name in DEFAULT_HOST_FIELDS:
            value = kwargs.get(field_name)
            if isinstance(value, str) and value.strip():
                return value
        return ""

    def run(self, guard: ScopeGuard, **kwargs: Any) -> ToolResult:
        target = self._extract_host_value(kwargs)
        if self.requires_scope_check:
            if not target:
                raise ScopeViolation(
                    f"'{self.name}' is scope-checked but none of {DEFAULT_HOST_FIELDS} (or the "
                    "configured host_fields override) was present with a value in its "
                    "arguments, so no host could be authorized. Add a host_fields entry in the "
                    "MCP server config naming this tool's real argument, or set "
                    "non_scope_checked_tools if it genuinely never touches a network target."
                )
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
        except Exception:  # noqa: BLE001, S112 # nosec B112 - a bad external server shouldn't break startup
            continue
    return tools
