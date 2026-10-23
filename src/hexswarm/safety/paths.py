"""Confines operator/agent-supplied file paths to a designated working directory.

Several tools take a local file path as an argument: a wordlist, a username/password list, a
file to identify or extract strings from, a garak REST generator config. None of those are
network targets the ScopeGuard can check, so without a separate guard here an agent (including
one steered by a hostile target's prompt-injected tool output) could point one of them at
anything readable on the host, e.g. ~/.aws/credentials or /etc/passwd, and have its contents
come back as the tool's own output, right where the next LLM call reads it.

A legitimate wordlist, file-to-analyze or config lives inside a working directory the operator
set up for the engagement; that's the one place a path argument is confined to here. Resolve
symlinks before comparing, so a symlink inside the working directory that points outside it
doesn't provide an escape hatch.
"""
from __future__ import annotations

import os
from pathlib import Path


class PathConfinementError(Exception):
    """Raised when a supplied path resolves outside the allowed working directory."""


def working_directory() -> Path:
    """The directory local file paths are confined to.

    Defaults to the current working directory; set HEXSWARM_WORK_DIR to point at the actual
    engagement folder (wordlists, staged files, configs) when running from somewhere else.
    """
    configured = os.getenv("HEXSWARM_WORK_DIR")
    base = Path(configured) if configured else Path.cwd()
    return base.resolve()


def confine_path(raw_path: str, field_name: str) -> Path:
    """Resolves `raw_path` and raises PathConfinementError unless it's inside the working dir.

    Returns the resolved, confined Path for the caller to use (so a caller never operates on
    the original, unresolved string after this check passes).
    """
    if not raw_path or not raw_path.strip():
        raise PathConfinementError(f"{field_name} must not be empty.")
    root = working_directory()
    candidate = (root / raw_path).resolve() if not Path(raw_path).is_absolute() else Path(raw_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PathConfinementError(
            f"{field_name} ({raw_path!r}) resolves to {candidate}, outside the working "
            f"directory {root}. Set HEXSWARM_WORK_DIR to the engagement folder this path "
            "actually lives in, or move the file inside it."
        ) from exc
    return candidate
