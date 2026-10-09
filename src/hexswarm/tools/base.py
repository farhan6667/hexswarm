"""Tool base classes: the safe-adapter layer.

Every tool wraps a real CLI security tool (nmap, sqlmap, hydra, gobuster, ...)
via subprocess. Before running, a tool:

1. Asks the ScopeGuard to authorize its target + risk level.
2. Checks whether its underlying binary is actually installed (`shutil.which`).
   If not, it runs in SIMULATE mode: it returns a clearly-labeled synthetic
   result describing what it *would* run, instead of either crashing or
   silently doing nothing. This keeps the framework usable and testable on a
   machine that doesn't have the full offensive-security toolchain installed
   (e.g. this Windows dev box), while running for real on a properly
   provisioned Linux/Kali/WSL pentest host.
3. If `human_in_the_loop` is True on the call, the executor must obtain
   confirmation before invoking `run()`. HexSwarm defaults to fully
   autonomous execution once a scope file is loaded, but the hook exists for
   anyone who wants per-step confirmation back.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ClassVar

from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel


@dataclass
class ToolResult:
    tool_name: str
    target: str
    command: str
    simulated: bool
    success: bool
    output: str
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "target": self.target,
            "command": self.command,
            "simulated": self.simulated,
            "success": self.success,
            "output": self.output,
            "error": self.error,
        }


class Tool(ABC):
    """Base class for a single wrapped security tool."""

    name: ClassVar[str]
    description: ClassVar[str]
    binary: ClassVar[str]
    risk_level: ClassVar[ToolRiskLevel]
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Target host, IP, CIDR, or URL."},
        },
        "required": ["target"],
    }
    timeout_seconds: ClassVar[int] = 120

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    @abstractmethod
    def build_command(self, **kwargs: Any) -> list[str]:
        """Return the argv list for the underlying CLI tool."""

    def simulate(self, command: list[str], **kwargs: Any) -> str:
        """Default synthetic output when the binary is not installed."""
        return (
            f"[SIMULATED] '{self.binary}' is not installed on this host, so "
            f"{self.name} did not execute. The command that would have run:\n"
            f"  {shlex.join(command)}\n"
            "Install the tool on a proper pentest host (Kali/Linux/WSL) to get "
            "real output."
        )

    def run(self, guard: ScopeGuard, **kwargs: Any) -> ToolResult:
        target = kwargs.get("target", "")
        guard.authorize(target, self.risk_level)

        command = self.build_command(**kwargs)
        command_str = shlex.join(command)

        if not self.is_available():
            return ToolResult(
                tool_name=self.name,
                target=target,
                command=command_str,
                simulated=True,
                success=True,
                output=self.simulate(command, **kwargs),
            )

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            return ToolResult(
                tool_name=self.name,
                target=target,
                command=command_str,
                simulated=False,
                success=proc.returncode == 0,
                output=proc.stdout,
                error=proc.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            raw_output = exc.stdout
            output_str = (
                raw_output.decode(errors="replace") if isinstance(raw_output, bytes) else raw_output
            ) or ""
            return ToolResult(
                tool_name=self.name,
                target=target,
                command=command_str,
                simulated=False,
                success=False,
                output=output_str,
                error=f"Timed out after {self.timeout_seconds}s",
            )

    def to_openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema,
            },
        }


class ToolRegistry:
    """Holds every registered tool, keyed by name."""

    _tools: ClassVar[dict[str, Tool]] = {}

    @classmethod
    def register(cls, tool: Tool) -> Tool:
        cls._tools[tool.name] = tool
        return tool

    @classmethod
    def get(cls, name: str) -> Tool:
        if name not in cls._tools:
            raise KeyError(f"No tool registered under name '{name}'.")
        return cls._tools[name]

    @classmethod
    def all(cls) -> dict[str, Tool]:
        return dict(cls._tools)

    @classmethod
    def for_phase(cls, risk_levels: list[ToolRiskLevel]) -> dict[str, Tool]:
        return {n: t for n, t in cls._tools.items() if t.risk_level in risk_levels}

    @classmethod
    def schemas_for(cls, tools: list[Tool]) -> list[dict[str, Any]]:
        return [t.to_openai_schema() for t in tools]
