"""Scope and authorization guard.

HexSwarm agents execute offensive-security tooling. Regardless of whether
human-in-the-loop confirmation is enabled, every tool invocation that touches
a network target MUST be checked against an explicit, user-authored scope
file before it runs. This is not optional: it is the one guardrail that stays
on even in fully-autonomous mode.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit

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
    def _extract_host(target: str) -> str | None:
        """Pulls the bare host out of a target, with or without a URL scheme.

        Several tools (web_vuln_scan, directory_brute, sql_injection_scan,
        http_fingerprint, ...) take a full URL like 'https://example.com/admin'
        as their target. Matching that whole string against a scope entry
        written as a domain ('*.example.com') would never succeed, since the
        scheme and path are part of the string being glob-matched. Scope
        files are written in terms of hosts, so targets are reduced to their
        host before matching.

        A target with no '://' used to be matched against scope patterns
        completely unparsed. Since fnmatch's '*' matches any character
        including '/', '?' and '@', an allow pattern like '*.lab.local'
        then also matched a crafted value such as 'evil.com/?x.lab.local':
        the pattern's leading '*' simply ate everything up to the real
        suffix. Parsing every target through the same authority grammar
        (prepending '//' when no scheme is present, exactly what a bare
        'host[:port]' or 'user@host' already is) extracts the real host
        component the same way regardless of whether a scheme was given,
        so the match happens on an actual host, never on an unparsed
        string a caller shaped to smuggle one past the glob.

        Returns None when no single clean host can be extracted (including
        an empty or whitespace-only target), so a caller fails closed
        instead of falling back to matching raw, un-parsed text.
        """
        target = target.strip()
        if not target:
            return None
        try:
            # A bare IPv4/IPv6 literal (optionally unbracketed IPv6, e.g. '::1')
            # is valid input but not valid URL authority syntax; check it
            # directly before attempting to parse it as one.
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass
        candidate = target if "://" in target else f"//{target}"
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            return None
        host = parsed.hostname
        if not host:
            return None
        return host.rstrip(".")

    @staticmethod
    def _label_glob_match(pattern: str, host: str) -> bool:
        """Matches `host` against a dot-label glob, where '*' stands for exactly one label.

        Found by an adversarial review: `fnmatch` treats '*' as "any characters at all",
        including dots, so a pattern like '10.10.10.*' (written to mean "any value in this
        last octet") also matched '10.10.10.evil.com': the trailing '*' simply absorbed the
        extra '.evil.com' with nothing anchoring it. SECURITY.md used to claim the opposite
        ("an octet-style wildcard pattern only ever matches hosts under that same prefix"),
        which was false and has been corrected.

        Rules, applied per dot-separated label:
        - A literal label must match the corresponding target label exactly (case-insensitive).
        - A label that is exactly '*' matches exactly one target label, UNLESS it is the
          pattern's first label, in which case it matches one or more leading target labels
          (the conventional '*.example.com' subdomain-wildcard meaning).
        - A label containing '*' mixed with other characters (e.g. 'host-*') is not
          supported; it never matches anything (fail closed, rather than silently falling
          back to an unanchored match).
        - Total label count must line up exactly everywhere except where the leading '*'
          absorbed extra labels, so nothing can be appended after the pattern's real
          right-hand boundary the way it previously could.
        """
        pattern_labels = pattern.split(".")
        host_labels = host.split(".")
        if any(label != "*" and "*" in label for label in pattern_labels):
            return False
        if pattern_labels and pattern_labels[0] == "*":
            fixed = pattern_labels[1:]
            if len(host_labels) < len(fixed) + 1:
                return False
            tail = host_labels[len(host_labels) - len(fixed):]
            consumed_leading = host_labels[:len(host_labels) - len(fixed)]
            if not consumed_leading:
                return False
            return all(f == "*" or f == t for f, t in zip(fixed, tail))
        if len(pattern_labels) != len(host_labels):
            return False
        return all(p == "*" or p == h for p, h in zip(pattern_labels, host_labels))

    def _matches(self, pattern: str, raw_target: str) -> bool:
        pattern = pattern.strip()
        target = self._extract_host(raw_target)
        if target is None:
            return False
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
        # Dot-label glob match for hostnames/domains/octet patterns, e.g. *.example.com or
        # 10.10.10.*. Not fnmatch: see _label_glob_match for why.
        return self._label_glob_match(pattern.lower(), target.lower())

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
