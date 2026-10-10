# Contributing to HexSwarm

Thanks for considering it. This is a young project built in the open, and it gets better when people who
actually run offensive-security tooling try it and say what's missing.

## Ways to help

- **A compatibility report** from a real pentest host (Kali, a hardened Linux box, WSL) with the full
  toolchain installed. Most of this was built and tested in simulate mode, so real tool output against a
  real lab target is the most valuable thing you can send.
- **A new tool adapter** for something HexSwarm doesn't wrap yet (see "Adding a tool" below).
- **A fix, a test, or a clearer sentence** in the docs.
- **A question or an idea** in [Discussions](https://github.com/farhan6667/hexswarm/discussions). Not
  everything has to be an issue.

Look for [good first issue](https://github.com/farhan6667/hexswarm/labels/good%20first%20issue) and
[help wanted](https://github.com/farhan6667/hexswarm/labels/help%20wanted) if you're not sure where to start.
Comment that you're taking one so two people don't do the same work.

## Setup

```bash
git clone https://github.com/farhan6667/hexswarm.git
cd hexswarm
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check src tests
pytest -q
```

Both need to be clean. Tests are fully offline and mocked (no API keys, no real tool binaries required), so
there's no excuse for "works on my machine."

## Adding a tool

A new tool is a `Tool` subclass in `src/hexswarm/tools/{recon,scan,exploit,privesc}.py`, registered with
`ToolRegistry.register(...)` at module import time. It needs:

- A `risk_level` from `ToolRiskLevel` that honestly reflects what it does (don't mark something `read_only`
  if it sends crafted packets at a target)
- A `build_command()` that returns an argv list, never a shell string and never `shell=True`
- A docstring/`description` clear enough that an LLM agent can decide when to call it from the name and
  description alone
- At least one test that checks `build_command()` output and one that exercises simulate mode

## Adding an agent / changing the pipeline

Phase agents live in `src/hexswarm/agents/specialized.py`. If you're proposing a new phase or a different
handoff pattern, open an issue first. The orchestrator's linear, auditable ordering is a deliberate choice
(see the README's "why HexSwarm exists" section), so a PR that makes it more dynamic needs to explain how it
keeps that auditability.

## Commit style

Plain, descriptive commit messages. No need to follow a strict format, but say what changed and why in the
body if it's not obvious from the subject line.

## Reporting bugs vs. security issues

Regular bugs: open a GitHub issue. Anything that lets HexSwarm bypass its own scope guard, or any other
security issue in HexSwarm's own code: see [SECURITY.md](SECURITY.md) instead, don't open a public issue.

## Hacktoberfest

This repo carries the `hacktoberfest` topic. A pull request is welcome whether or not you're taking part in
the event, and low-effort changes that only exist to count toward it will be closed politely.

## Be kind

Be patient with newcomers and with the maintainer. Our [Code of Conduct](CODE_OF_CONDUCT.md) is short: be
respectful, assume good intent, and keep feedback about the work, not the person. One addition specific to
an offensive-security tool: see its note about what "a scope-aware adapter" means versus a ready-made
attack chain against a named target.
