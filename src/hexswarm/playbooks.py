"""Named, reusable engagement presets.

A playbook bundles the things you'd otherwise retype every run: the goal
phrasing, which phases to run and in what order, and the max risk level to
cap at. It does NOT bundle a scope or a target: those are per-engagement and
must always be supplied explicitly, so a playbook can never widen what you're
authorized to touch. It only shapes *how* HexSwarm works within a scope you
provide each time.

This is the lightweight version of the "playbook" idea other frameworks ship
(bug-bounty / CI / internal-network / CTF presets), kept to plain data so a
playbook is auditable at a glance and can't smuggle in behavior.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_BUILTIN_DIR = Path(__file__).parent / "data" / "playbooks"


@dataclass
class Playbook:
    name: str
    description: str
    goal: str
    phases: list[str] = field(default_factory=lambda: ["recon", "scan", "exploit", "privesc"])
    max_risk_level: str | None = None  # if set, overrides the scope file's cap downward only

    @classmethod
    def from_dict(cls, data: dict) -> Playbook:
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            goal=data["goal"],
            phases=list(data.get("phases", ["recon", "scan", "exploit", "privesc"])),
            max_risk_level=data.get("max_risk_level"),
        )


def load_playbook(path: str | Path) -> Playbook:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Playbook not found: {path}")
    return Playbook.from_dict(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


def builtin_playbooks() -> dict[str, Playbook]:
    """Loads the playbooks shipped with HexSwarm, keyed by name."""
    out: dict[str, Playbook] = {}
    if not _BUILTIN_DIR.exists():
        return out
    for yaml_file in sorted(_BUILTIN_DIR.glob("*.yaml")):
        pb = load_playbook(yaml_file)
        out[pb.name] = pb
    return out


def resolve_playbook(name_or_path: str) -> Playbook:
    """Resolves a playbook by built-in name first, then as a file path."""
    builtins = builtin_playbooks()
    if name_or_path in builtins:
        return builtins[name_or_path]
    return load_playbook(name_or_path)
