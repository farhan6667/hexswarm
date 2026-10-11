"""Bundled vulnerable labs: disposable, locally-hosted targets for real validation.

The honest problem this solves: most of HexSwarm was built and tested in
simulate mode, so "does the real pipeline actually work against a real app?"
was unanswered. A bundled vulnerable lab (OWASP Juice Shop and friends) that
spins up on localhost, gets attacked, and tears down gives a safe, repeatable
way to exercise the whole thing against a genuinely vulnerable target without
touching anyone else's systems.

This module just builds the `docker compose` commands; it doesn't reimplement
container management. Each lab is a compose file under examples/labs/ that
binds to localhost only, paired with a ready-made scope file. The commands are
built as argv lists (never a shell string), so there's no new injection
surface.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

_LABS_DIR = Path(__file__).parent.parent.parent / "examples" / "labs"


def labs_dir() -> Path:
    return _LABS_DIR


def available_labs() -> dict[str, Path]:
    """Maps lab name -> its compose file. A lab 'foo' is examples/labs/foo.yaml."""
    if not _LABS_DIR.exists():
        return {}
    return {
        f.stem: f
        for f in sorted(_LABS_DIR.glob("*.yaml"))
        if not f.name.endswith(".scope.yaml")
    }


def scope_file_for(name: str) -> Path | None:
    candidate = _LABS_DIR / f"{name}.scope.yaml"
    return candidate if candidate.exists() else None


def docker_available() -> bool:
    return shutil.which("docker") is not None


def compose_command(compose_file: Path, action: str) -> list[str]:
    """Builds the `docker compose` argv for an action ('up' or 'down').

    'up' runs detached so the lab keeps running in the background for a scan;
    'down' removes the containers so nothing is left lying around.
    """
    base = ["docker", "compose", "-f", str(compose_file)]
    if action == "up":
        return [*base, "up", "-d"]
    if action == "down":
        return [*base, "down"]
    raise ValueError(f"Unknown lab action: {action!r} (expected 'up' or 'down').")


def run_lab_action(name: str, action: str) -> subprocess.CompletedProcess:
    """Starts or stops a named lab. Raises KeyError for an unknown lab name."""
    labs = available_labs()
    if name not in labs:
        raise KeyError(f"Unknown lab '{name}'. Available: {', '.join(labs) or '(none)'}")
    command = compose_command(labs[name], action)
    return subprocess.run(command, capture_output=True, text=True, check=False)  # nosec B603
