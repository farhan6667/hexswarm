"""HexSwarm's own small CTF-style benchmark runner.

The point isn't to rival Cybench or NYU-CTF Bench on scale, it's to give
every HexSwarm release (and every model configuration) one honest, checkable
number instead of a vibe: "solved 5/6 local challenges" is something a
reader can verify by cloning the repo and running the same command, the same
way those bigger benchmarks are meant to be read.

Each challenge gets a brand-new Agent and FindingsStore, so one challenge's
tool-call history never leaks into the next one's context.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from hexswarm.agents.base import Agent
from hexswarm.memory.findings import FindingsStore
from hexswarm.safety.guard import ScopeGuard


@dataclass
class BenchmarkChallenge:
    id: str
    file: Path
    goal: str
    flag: str


@dataclass
class BenchmarkResult:
    challenge_id: str
    solved: bool
    summary: str


@dataclass
class BenchmarkReport:
    results: list[BenchmarkResult] = field(default_factory=list)

    @property
    def solved_count(self) -> int:
        return sum(1 for r in self.results if r.solved)

    @property
    def total_count(self) -> int:
        return len(self.results)

    def to_markdown(self) -> str:
        lines = [
            "# HexSwarm benchmark results",
            "",
            f"**{self.solved_count}/{self.total_count} solved**",
            "",
            "| Challenge | Result |",
            "|---|---|",
        ]
        for r in self.results:
            mark = "PASS" if r.solved else "FAIL"
            lines.append(f"| {r.challenge_id} | {mark} |")
        return "\n".join(lines) + "\n"


def load_challenges(manifest_path: str | Path) -> list[BenchmarkChallenge]:
    manifest_path = Path(manifest_path)
    if not manifest_path.exists():
        raise FileNotFoundError(f"Benchmark manifest not found: {manifest_path}")
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    base_dir = manifest_path.parent
    return [
        BenchmarkChallenge(
            id=entry["id"],
            file=base_dir / entry["file"],
            goal=entry["goal"],
            flag=entry["flag"],
        )
        for entry in data.get("challenges", [])
    ]


def run_benchmark(
    challenges: list[BenchmarkChallenge],
    agent_factory: Callable[[], Agent],
    guard_factory: Callable[[], ScopeGuard],
) -> BenchmarkReport:
    """Runs one fresh agent per challenge and checks whether its summary contains the flag.

    `agent_factory`/`guard_factory` are callables rather than shared instances so every
    challenge gets an independent agent and scope guard, never one left over from the
    previous challenge's run.
    """
    report = BenchmarkReport()
    for challenge in challenges:
        agent = agent_factory()
        guard = guard_factory()
        findings = FindingsStore(engagement_name=f"bench-{challenge.id}")
        summary = agent.run(
            goal=challenge.goal,
            target=str(challenge.file),
            guard=guard,
            findings=findings,
        )
        solved = challenge.flag in summary
        report.results.append(
            BenchmarkResult(challenge_id=challenge.id, solved=solved, summary=summary)
        )
    return report
