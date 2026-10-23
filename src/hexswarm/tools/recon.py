"""Read-only and active-recon tools: information gathering before anything touches a target hard."""
from __future__ import annotations

import re
from typing import Any, ClassVar

from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel
from hexswarm.safety.paths import confine_path
from hexswarm.tools.base import Tool, ToolRegistry, ToolResult


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

    # nmap's own "-p-" syntax (all 65535 ports) is a literal '-' as -p's argument, so unlike
    # most fields here, a value that merely starts with '-' isn't automatically invalid.
    # Instead of rejecting on that one character, this restricts the whole value to what a
    # real port spec can contain (digits, commas, dashes, or exactly '-' for all ports),
    # which rejects an injected flag like '-sS' or '-oN/path' just as effectively.
    _PORTS_RE = re.compile(r"^-$|^[0-9][0-9,\-]*$")

    def build_command(self, **kwargs: Any) -> list[str]:
        ports = kwargs.get("ports", "")
        cmd = [self.binary, "-sV", "-T4", "--open"]
        if ports and ports != "top-1000":
            if not self._PORTS_RE.match(ports):
                raise ValueError(f"ports must be digits/commas/dashes (or '-' for all ports); got {ports!r}.")
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


class HttpProbe(Tool):
    name: ClassVar[str] = "http_probe"
    description: ClassVar[str] = (
        "Probes a host or list of hosts for live HTTP/HTTPS services using httpx (ProjectDiscovery), "
        "reporting status code, title, and detected technologies. Use this to turn a list of hosts "
        "from DNS enumeration into the subset that actually serves web content."
    )
    binary: ClassVar[str] = "httpx"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.ACTIVE_RECON
    timeout_seconds: ClassVar[int] = 120

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "-u", kwargs["target"], "-silent", "-title", "-status-code", "-tech-detect"]


class FastPortScan(Tool):
    name: ClassVar[str] = "fast_port_scan"
    description: ClassVar[str] = (
        "Fast SYN/CONNECT port discovery across a host or CIDR using naabu (ProjectDiscovery). "
        "Faster than a full nmap -sV sweep for finding which ports are open; follow up with "
        "port_scan for service/version detail on the ports naabu reports."
    )
    binary: ClassVar[str] = "naabu"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.ACTIVE_RECON
    timeout_seconds: ClassVar[int] = 180

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "-host", kwargs["target"], "-silent"]


class WebCrawl(Tool):
    name: ClassVar[str] = "web_crawl"
    description: ClassVar[str] = (
        "Crawls a web target to enumerate endpoints, URLs, and parameters using katana "
        "(ProjectDiscovery). Use this to map a web app's surface before vulnerability scanning."
    )
    binary: ClassVar[str] = "katana"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.ACTIVE_RECON
    timeout_seconds: ClassVar[int] = 300

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "-u", kwargs["target"], "-silent"]


class DnsResolve(Tool):
    name: ClassVar[str] = "dns_resolve"
    description: ClassVar[str] = (
        "Resolves and validates DNS records for a host or list of hosts using dnsx "
        "(ProjectDiscovery), filtering a candidate list down to the ones that actually resolve."
    )
    binary: ClassVar[str] = "dnsx"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.READ_ONLY
    timeout_seconds: ClassVar[int] = 90

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "-d", kwargs["target"], "-silent", "-a", "-resp"]


class SubdomainEnum(Tool):
    name: ClassVar[str] = "subdomain_enum"
    description: ClassVar[str] = (
        "Passive subdomain and attack-surface enumeration for a root domain using OWASP Amass. "
        "Pulls from certificate transparency, passive DNS, and other open sources without actively "
        "probing the target, so it stays read-only recon. Feed the results into http_probe or "
        "dns_resolve to find the ones that are actually live."
    )
    binary: ClassVar[str] = "amass"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.READ_ONLY
    timeout_seconds: ClassVar[int] = 300
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Root domain, e.g. example.com"},
        },
        "required": ["target"],
    }

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "enum", "-passive", "-d", kwargs["target"]]


class OsintHarvest(Tool):
    name: ClassVar[str] = "osint_harvest"
    description: ClassVar[str] = (
        "Passive OSINT collection for a domain using theHarvester: email addresses, employee "
        "names, subdomains, and hosts pulled from public search engines and data sources. "
        "Read-only, it queries third-party sources rather than the target itself."
    )
    binary: ClassVar[str] = "theHarvester"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.READ_ONLY
    timeout_seconds: ClassVar[int] = 300
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Root domain, e.g. example.com"},
            "sources": {
                "type": "string",
                "description": "Comma-separated theHarvester sources. Defaults to a fast, key-free set.",
            },
        },
        "required": ["target"],
    }

    _SOURCES_RE = re.compile(r"^[A-Za-z0-9_]+(,[A-Za-z0-9_]+)*$")

    def build_command(self, **kwargs: Any) -> list[str]:
        sources = kwargs.get("sources") or "crtsh,duckduckgo,bing,otx"
        # Source names are plain words; restricting the character set (rather than only
        # rejecting a leading '-') closes a flag injected via -b's own argument too.
        if not self._SOURCES_RE.match(sources):
            raise ValueError(f"sources must be comma-separated plain names; got {sources!r}.")
        return [self.binary, "-d", kwargs["target"], "-b", sources]


class SubdomainTakeover(Tool):
    name: ClassVar[str] = "subdomain_takeover"
    description: ClassVar[str] = (
        "Checks a list of subdomains for dangling DNS records that can be taken over (unclaimed "
        "cloud services, dropped CNAME targets) using SubOver. Pass an operator-staged file of "
        "subdomains, one per line, typically the output of subdomain_enum."
    )
    binary: ClassVar[str] = "SubOver"
    risk_level: ClassVar[ToolRiskLevel] = ToolRiskLevel.ACTIVE_RECON
    # 'target' is the staged file's path, not a network host, so it can't satisfy the
    # host/CIDR/domain scope matcher and the base Tool.run() scope check is skipped for it.
    # The actual network targets are the subdomains INSIDE that file, each one real traffic
    # SubOver will send: run() below reads them and scope-checks every single one itself,
    # since skipping requires_scope_check here must not mean skipping scope checking
    # altogether.
    requires_scope_check: ClassVar[bool] = False
    timeout_seconds: ClassVar[int] = 300
    parameters_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Path to a file of subdomains to check, one per line.",
            },
        },
        "required": ["target"],
    }

    def run(self, guard: ScopeGuard, **kwargs: Any) -> ToolResult:
        path = confine_path(kwargs["target"], "target")
        subdomains = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        out_of_scope = []
        for subdomain in subdomains:
            try:
                guard.check_target(subdomain)
            except ScopeViolation:
                out_of_scope.append(subdomain)
        if out_of_scope:
            raise ScopeViolation(
                f"{kwargs['target']} lists {len(out_of_scope)} subdomain(s) not covered by any "
                f"allow rule in scope '{guard.engagement_name}': {', '.join(out_of_scope[:10])}"
                f"{'...' if len(out_of_scope) > 10 else ''}. Every subdomain in this file is a "
                "real target SubOver will probe; fix the list or the scope file before running."
            )
        return super().run(guard, **kwargs)

    def build_command(self, **kwargs: Any) -> list[str]:
        return [self.binary, "-l", str(confine_path(kwargs["target"], "target"))]


ToolRegistry.register(WhoisLookup())
ToolRegistry.register(DnsEnum())
ToolRegistry.register(PortScan())
ToolRegistry.register(HttpFingerprint())
ToolRegistry.register(HttpProbe())
ToolRegistry.register(FastPortScan())
ToolRegistry.register(WebCrawl())
ToolRegistry.register(DnsResolve())
ToolRegistry.register(SubdomainEnum())
ToolRegistry.register(OsintHarvest())
ToolRegistry.register(SubdomainTakeover())
