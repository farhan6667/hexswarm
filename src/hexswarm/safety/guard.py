"""Scope and authorization guard.

HexSwarm agents execute offensive-security tooling. Regardless of whether
human-in-the-loop confirmation is enabled, every tool invocation that touches
a network target MUST be checked against an explicit, user-authored scope
file before it runs. This is not optional: it is the one guardrail that stays
on even in fully-autonomous mode.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ToolRiskLevel(str, Enum):
    """Risk classification for a tool, used for logging and reporting."""

    READ_ONLY = "read_only"       # pure information gathering, no packets to target beyond passive lookups
    ACTIVE_RECON = "active_recon"  # port scans, service fingerprinting
    INTRUSIVE = "intrusive"        # vuln scanning, brute force, fuzzing
    EXPLOIT = "exploit"            # exploitation, payload delivery
    POST_EXPLOIT = "post_exploit"  # privilege escalation, lateral movement, persistence


class ScopeViolation(Exception):
    """Raised when a tool call targets something outside the authorized scope."""


@dataclass
class ScopeGuard:
    """Validates tool targets against an authorized engagement scope.

    The scope file is the single source of truth for what an agent is allowed
    to touch. A target that is not covered by at least one allow entry, or
    that matches a deny entry, is rejected before the tool ever runs.
    """

    engagement_name: str
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    max_risk_level: ToolRiskLevel = ToolRiskLevel.POST_EXPLOIT
    authorized_by: str = ""
    notes: str = ""

    @classmethod
    def from_file(cls, path: str | Path) -> ScopeGuard:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(
                f"Scope file not found: {path}. HexSwarm refuses to run against "
                "any target without an explicit scope file. See examples/scope.example.yaml."
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not data.get("allow"):
            raise ValueError(
                "Scope file has an empty or missing 'allow' list. "
                "Refusing to run with an unbounded scope."
            )
        return cls(
            engagement_name=data.get("engagement_name", "unnamed-engagement"),
            allow=list(data.get("allow", [])),
            deny=list(data.get("deny", [])),
            max_risk_level=ToolRiskLevel(data.get("max_risk_level", "post_exploit")),
            authorized_by=data.get("authorized_by", ""),
            notes=data.get("notes", ""),
        )

    @staticmethod
    def _extract_host(target: str) -> str:
        """Pulls the bare host out of a URL-style target.

        Several tools (web_vuln_scan, directory_brute, sql_injection_scan,
        http_fingerprint, ...) take a full URL like 'https://example.com/admin'
        as their target. Matching that whole string against a scope entry
        written as a domain ('*.example.com') would never succeed, since the
        scheme and path are part of the string being glob-matched. Scope
        files are written in terms of hosts, so URL targets are reduced to
        their host before matching.
        """
        target = target.strip()
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        return target

    def _matches(self, pattern: str, raw_target: str) -> bool:
        pattern = pattern.strip()
        target = self._extract_host(raw_target)
        # CIDR / IP network match
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            try:
                ip = ipaddress.ip_address(target)
                return ip in network
            except ValueError:
                return False
        except ValueError:
            pass
        # Glob match for hostnames/domains, e.g. *.example.com
        return fnmatch.fnmatch(target.lower(), pattern.lower())

    def check_target(self, target: str) -> None:
        """Raise ScopeViolation if target is not explicitly authorized."""
        for pattern in self.deny:
            if self._matches(pattern, target):
                raise ScopeViolation(
                    f"Target '{target}' matches deny rule '{pattern}' in scope "
                    f"'{self.engagement_name}'."
                )
        for pattern in self.allow:
            if self._matches(pattern, target):
                return
        raise ScopeViolation(
            f"Target '{target}' is not covered by any allow rule in scope "
            f"'{self.engagement_name}'. Add it to the scope file to proceed."
        )

    def check_risk(self, level: ToolRiskLevel) -> None:
        order = list(ToolRiskLevel)
        if order.index(level) > order.index(self.max_risk_level):
            raise ScopeViolation(
                f"Tool risk level '{level.value}' exceeds the engagement's "
                f"max_risk_level '{self.max_risk_level.value}'."
            )

    def authorize(self, target: str, risk_level: ToolRiskLevel) -> None:
        """Convenience call combining target + risk checks."""
        self.check_target(target)
        self.check_risk(risk_level)
