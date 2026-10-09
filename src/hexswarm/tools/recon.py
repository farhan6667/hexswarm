"""Read-only and active-recon tools: information gathering before anything touches a target hard."""
from __future__ import annotations

from typing import Any, ClassVar

from hexswarm.safety.guard import ToolRiskLevel
from hexswarm.tools.base import Tool, ToolRegistry


class WhoisLookup(Tool):
    name: ClassVar[str] = "whois_lookup"
    description: ClassVar[str] = "Passive WHOIS registration lookup for a domain."
    binary: ClassVar[str] = "whois"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.READ_ONLY
    timeout_seconds: ClassVar[int] = 30

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, kwargs["target"]]


class DnsEnum(Tool):
    name: ClassVar[str] = "dns_enum"
    description: ClassVar[str] = (
        "Passive DNS record enumeration (A/AAAA/MX/TXT/NS) for a domain using subfinder."
    )
    binary: ClassVar[str] = "subfinder"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.READ_ONLY
    timeout_seconds: ClassVar[int] = 90
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Root domain, e.g. example.com"},
        },
        "required": ["target"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "-d", kwargs["target"], "-silent"]


class PortScan(Tool):
    name: ClassVar[str] = "port_scan"
    description: ClassVar[str] = (
        "Active TCP port scan + service/version fingerprinting against a host or CIDR using nmap. "
        "This is active recon: it sends packets to the target."
    )
    binary: ClassVar[str] = "nmap"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.ACTIVE_RECON
    timeout_seconds: ClassVar[int] = 300
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host, IP, or CIDR range to scan."},
            "ports": {
                "type": "string",
                "description": "Port range, e.g. '1-1000' or 'top-1000'. Defaults to top 1000.",
            },
        },
        "required": ["target"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        ports = kwargs.get("ports", "")
        cmd = [self.binary, "-sV", "-T4", "--open"]
        if ports and ports != "top-1000":
            cmd += ["-p", ports]
        cmd.append(kwargs["target"])
        return cmd


class HttpFingerprint(Tool):
    name: ClassVar[str] = "http_fingerprint"
    description: ClassVar[str] = (
        "Fingerprints web technologies (server, framework, CMS) running behind an HTTP(S) endpoint."
    )
    binary: ClassVar[str] = "whatweb"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.ACTIVE_RECON
    timeout_seconds: ClassVar[int] = 60

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "-a", "3", kwargs["target"]]


ToolRegistry.register(WhoisLookup())
ToolRegistry.register(DnsEnum())
ToolRegistry.register(PortScan())
ToolRegistry.register(HttpFingerprint())
