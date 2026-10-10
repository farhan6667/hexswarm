"""A small local knowledge base of attack hints, keyed by service/product.

This is a lightweight, offline version of the "knowledge-hint injection"
idea from CRAKEN-style CTF agents: instead of relying purely on the LLM's
training data (which goes stale and can hallucinate CVE numbers), the agent
grounds its suggestions in a curated, versioned, human-reviewed hint file
that ships with the framework and that users can extend for their own
environments.

Lookup is alias-and-score based, not a vector/embedding search: every hint
carries a list of aliases (product names, common banner substrings), and a
query is ranked by how many distinct aliases it matches, most relevant
first. That's a meaningfully better signal than a flat "does any key appear
as a substring" check once the corpus has more than a handful of entries
(two services can share generic substrings), without needing an embeddings
model or any network call to use. It's deliberately not marketed as more
than that: this is a scored keyword match, not semantic retrieval.

This is intentionally NOT an exploit database. It stores high-level
checklist-style hints ("check for anonymous bind", "try default creds from
vendor X") -- never working exploit code, never a one-click weaponized
payload. Operators still need searchsploit / Metasploit / manual work for
actual exploitation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_DEFAULT_PATH = Path(__file__).parent / "data" / "hints.yaml"


@dataclass
class Hint:
    service: str
    aliases: list[str] = field(default_factory=list)
    checklist: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


class KnowledgeBase:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else _DEFAULT_PATH
        self._hints: dict[str, Hint] = {}
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        for service, body in data.items():
            key = service.lower()
            aliases = {key, *(a.lower() for a in body.get("aliases", []))}
            self._hints[key] = Hint(
                service=service,
                aliases=sorted(aliases),
                checklist=list(body.get("checklist", [])),
                references=list(body.get("references", [])),
            )

    def lookup(self, service_or_banner: str, top_k: int = 5) -> list[Hint]:
        """Ranks known hints by how many of their aliases appear in the query text.

        A hint with two matching aliases (e.g. both "ssh" and "openssh" show up in
        the banner) ranks above one with a single generic substring match, instead of
        every hint whose key happens to appear anywhere in the text coming back in
        arbitrary, equally-weighted order.
        """
        needle = service_or_banner.lower()
        scored: list[tuple[int, Hint]] = []
        for hint in self._hints.values():
            score = sum(1 for alias in hint.aliases if alias in needle)
            if score > 0:
                scored.append((score, hint))
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [hint for _, hint in scored[:top_k]]

    def all_services(self) -> list[str]:
        return list(self._hints.keys())
