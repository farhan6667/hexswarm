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
        "Runs a pre-staged linpeas.sh over SSH on a Linux host that has already been "
        "compromised, to enumerate local privilege escalation vectors: SUID binaries, cron "
        "jobs, writable services, kernel exploits, etc. Does NOT download linpeas at runtime: "
        "fetching and checksumming the script is an explicit, operator-controlled step before "
        "an engagement, not something an agent does live against a target over the open "
        "internet mid-engagement. Stage the script on the compromised host first (e.g. via an "
        "existing file-transfer foothold) and point remote_script_path at it."
    )
    binary: ClassVar[str] = "ssh"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.POST_EXPLOIT
    timeout_seconds: ClassVar[int] = 300
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Host or IP of the already-compromised machine (scope-checked).",
            },
            "ssh_user": {
                "type": "string",
                "description": "Username for the existing SSH foothold on the compromised host.",
            },
            "remote_script_path": {
                "type": "string",
                "description": "Path to the already-staged linpeas.sh on the remote host.",
            },
        },
        "required": ["target", "ssh_user"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        # nosec B108: this is a path on the *remote*, already-compromised host, referenced
        # inside an ssh command string. It never touches this machine's own /tmp, so the
        # local-temp-file-race concern that rule exists for doesn't apply here.
        remote_script_path = kwargs.get("remote_script_path", "/tmp/linpeas.sh")  # nosec B108
        connection = f"{kwargs['ssh_user']}@{kwargs['target']}"
        return [self.binary, connection, f"bash {remote_script_path}"]


class WindowsPrivescEnum(Tool):
    name: ClassVar[str] = "windows_privesc_enum"
    description: ClassVar[str] = (
        "Runs a WinPEAS-style enumeration via PowerShell remoting (Invoke-Command -FilePath) "
        "against an already-compromised Windows host to find local privilege escalation "
        "vectors: misconfigured services, unquoted paths, stored credentials, "
        "AlwaysInstallElevated. Requires an existing WinRM-reachable session on that host."
    )
    # The actual argv[0] executed locally is pwsh; the remote host is reached
    # over WinRM via -ComputerName, not by a local winpeas.exe binary.
    binary: ClassVar[str] = "pwsh"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.POST_EXPLOIT
    timeout_seconds: ClassVar[int] = 300
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "PowerShell remoting target (ComputerName) for the compromised host.",
            },
            "remote_script_path": {
                "type": "string",
                "description": "Local path to the WinPEAS-style .ps1 script sent over WinRM.",
            },
        },
        "required": ["target"],
    }

    @staticmethod
    def _escape_single_quoted(value: str) -> str:
        """Escape a value for safe interpolation inside a single-quoted PowerShell literal.

        Without this, a target or path containing a single quote could break out of the
        quoted literal and inject arbitrary PowerShell into the *local* pwsh invocation,
        before any remote connection is even made.
        """
        return value.replace("'", "''")

    def build_command(self, **kwargs: Any) -> list[str]:
        computer_name = self._escape_single_quoted(kwargs["target"])
        script_path = self._escape_single_quoted(kwargs.get("remote_script_path", "./winpeas.ps1"))
        return [
            self.binary, "-NonInteractive", "-Command",
            f"Invoke-Command -ComputerName '{computer_name}' -FilePath '{script_path}'",
        ]


ToolRegistry.register(LinuxPrivescEnum())
ToolRegistry.register(WindowsPrivescEnum())
