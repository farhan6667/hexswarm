"""A small local knowledge base of attack hints, keyed by service/product.

This is a lightweight, offline version of the "knowledge-hint injection"
idea from CRAKEN-style CTF agents: instead of relying purely on the LLM's
training data (which goes stale and can hallucinate CVE numbers), the agent
grounds its suggestions in a curated, versioned, human-reviewed hint file
that ships with the framework and that users can extend for their own
environments.

This is intentionally NOT an exploit database. It stores high-level
checklist-style hints ("check for anonymous bind", "try default creds from
vendor X") -- never working exploit code, never a one-click weaponized
payload. Operators still need searchsploit / Metasploit / manual work for
actual exploitation.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_DEFAULT_PATH = Path(__file__).parent / "data" / "hints.yaml"


@dataclass
class Hint:
    service: str
    checklist: list[str]
    references: list[str]


class KnowledgeBase:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else _DEFAULT_PATH
        self._hints: dict[str, Hint] = {}
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        for service, body in data.items():
            self._hints[service.lower()] = Hint(
                service=service,
                checklist=list(body.get("checklist", [])),
                references=list(body.get("references", [])),
            )

    def lookup(self, service_or_banner: str) -> list[Hint]:
        """Fuzzy-match a banner/service string against known hint keys."""
        needle = service_or_banner.lower()
        return [hint for key, hint in self._hints.items() if key in needle]

    def all_services(self) -> list[str]:
        return list(self._hints.keys())
