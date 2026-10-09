"""Shared findings store: the one place every agent writes what it learned.

Agents in a swarm don't share a single context window, so handoffs would lose
information without a shared store. The Recon agent writes hosts/services
here, the VulnScan agent reads them to decide what to scan, and so on through
to the Report agent, which just reads everything back out at the end.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    phase: str          # "recon" | "scan" | "exploit" | "privesc"
    tool_name: str
    target: str
    summary: str
    severity: str = "info"  # "info" | "low" | "medium" | "high" | "critical"
    raw_output: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FindingsStore:
    """In-memory + optionally-persisted list of findings for one engagement."""

    def __init__(self, engagement_name: str, persist_path: str | Path | None = None) -> None:
        self.engagement_name = engagement_name
        self.persist_path = Path(persist_path) if persist_path else None
        self._findings: list[Finding] = []
        if self.persist_path and self.persist_path.exists():
            self._load()

    def add(self, finding: Finding) -> None:
        self._findings.append(finding)
        if self.persist_path:
            self._save()

    def all(self) -> list[Finding]:
        return list(self._findings)

    def by_phase(self, phase: str) -> list[Finding]:
        return [f for f in self._findings if f.phase == phase]

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self._findings if f.severity == severity]

    def summary_text(self) -> str:
        """Short text block handed to the next agent in the handoff chain."""
        if not self._findings:
            return "No findings recorded yet."
        lines = []
        for f in self._findings:
            lines.append(f"[{f.phase}/{f.severity}] {f.tool_name} on {f.target}: {f.summary}")
        return "\n".join(lines)

    def _save(self) -> None:
        if self.persist_path is None:
            raise RuntimeError("_save() called without a persist_path configured.")
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "engagement_name": self.engagement_name,
            "findings": [f.to_dict() for f in self._findings],
        }
        self.persist_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load(self) -> None:
        if self.persist_path is None:
            raise RuntimeError("_load() called without a persist_path configured.")
        data = json.loads(self.persist_path.read_text(encoding="utf-8"))
        self._findings = [Finding(**f) for f in data.get("findings", [])]
