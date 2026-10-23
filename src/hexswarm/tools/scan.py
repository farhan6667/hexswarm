"""Intrusive tools: vulnerability scanning, directory/content discovery, fuzzing."""
from __future__ import annotations

from typing import Any, ClassVar

from hexswarm.safety.guard import ToolRiskLevel
from hexswarm.safety.paths import confine_path
from hexswarm.tools.base import Tool, ToolRegistry, reject_leading_dash


class WebVulnScan(Tool):
    name: ClassVar[str] = "web_vuln_scan"
    description: ClassVar[str] = (
        "Runs nuclei against a URL with the default community template set to find known "
        "web vulnerabilities and misconfigurations."
    )
    binary: ClassVar[str] = "nuclei"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.INTRUSIVE
    timeout_seconds: ClassVar[int] = 600

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "-u", kwargs["target"], "-silent"]


class DirectoryBrute(Tool):
    name: ClassVar[str] = "directory_brute"
    description: ClassVar[str] = (
        "Brute-forces hidden directories and files on a web server using gobuster."
    )
    binary: ClassVar[str] = "gobuster"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.INTRUSIVE
    timeout_seconds: ClassVar[int] = 300
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Base URL, e.g. https://example.com"},
            "wordlist": {
                "type": "string",
                "description": "Path to wordlist file. Defaults to a small built-in list.",
            },
        },
        "required": ["target"],
    }

    _DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

    def build_command(self, **kwargs: Any) -> list[str]:
        wordlist = kwargs.get("wordlist")
        # The built-in default is a fixed system path, not operator/agent input, so it isn't
        # run through confine_path; anything actually supplied by a caller is.
        wordlist_path = (
            self._DEFAULT_WORDLIST if not wordlist else str(confine_path(wordlist, "wordlist"))
        )
        return [self.binary, "dir", "-u", kwargs["target"], "-w", wordlist_path, "-q"]


class SqlInjectionScan(Tool):
    name: ClassVar[str] = "sql_injection_scan"
    description: ClassVar[str] = (
        "Tests a URL parameter for SQL injection using sqlmap in batch (non-interactive) mode "
        "with conservative risk/level settings."
    )
    binary: ClassVar[str] = "sqlmap"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.INTRUSIVE
    timeout_seconds: ClassVar[int] = 600

    def build_command(self, **kwargs: Any) -> list[str]:
        return [
            self.binary,
            "-u", kwargs["target"],
            "--batch",
            "--risk=1",
            "--level=1",
        ]


class PasswordBruteForce(Tool):
    name: ClassVar[str] = "password_brute_force"
    description: ClassVar[str] = (
        "Credential brute-force against a network service (ssh, ftp, http-form, ...) using hydra. "
        "Requires explicit username/password list file paths supplied by the operator."
    )
    binary: ClassVar[str] = "hydra"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.INTRUSIVE
    timeout_seconds: ClassVar[int] = 900
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host or IP."},
            "service": {"type": "string", "description": "e.g. ssh, ftp, http-get"},
            "userlist": {"type": "string", "description": "Path to username list."},
            "passlist": {"type": "string", "description": "Path to password list."},
        },
        "required": ["target", "service", "userlist", "passlist"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        # 'service' is a trailing positional with no preceding flag of its own (unlike
        # userlist/passlist, which are each already consumed as the argument to -L/-P), so
        # a dash-leading value here is read by hydra's own getopt as an independent option
        # (-o to redirect output, -R to restore a session, etc.), not rejected as garbage.
        reject_leading_dash(kwargs["service"], "service")
        return [
            self.binary,
            "-L", str(confine_path(kwargs["userlist"], "userlist")),
            "-P", str(confine_path(kwargs["passlist"], "passlist")),
            kwargs["target"],
            kwargs["service"],
        ]


class XssScan(Tool):
    name: ClassVar[str] = "xss_scan"
    description: ClassVar[str] = (
        "Scans a URL for cross-site scripting and analyses its parameters using dalfox. More "
        "focused than the generic nuclei pass: it fuzzes parameters, verifies reflections, and "
        "detects and bypasses common WAFs. Intrusive, it sends payloads to the target."
    )
    binary: ClassVar[str] = "dalfox"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.INTRUSIVE
    timeout_seconds: ClassVar[int] = 600

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "url", kwargs["target"], "--silence", "--no-color"]


ToolRegistry.register(WebVulnScan())
ToolRegistry.register(DirectoryBrute())
ToolRegistry.register(SqlInjectionScan())
ToolRegistry.register(PasswordBruteForce())
ToolRegistry.register(XssScan())
