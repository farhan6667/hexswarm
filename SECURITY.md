# Security Policy

HexSwarm is a dual-use offensive-security framework, so we take reports about HexSwarm's own code seriously,
separate from how operators use it.

## Scope

This policy covers vulnerabilities **in HexSwarm itself**: the scope guard, the tool adapters, the CLI, the
LLM routing layer. It does not cover vulnerabilities you find in a third-party target while using HexSwarm
(report those through that target's own program or responsible disclosure process), and it is not a channel
for general support questions.

Things we'd specifically want to know about:

- A way to make `ScopeGuard` authorize a target it shouldn't (a pattern-matching bypass, a CIDR edge case, etc.)
- Command/argument injection in any tool adapter (`src/hexswarm/tools/`)
- Path traversal in findings/report persistence
- Dependency vulnerabilities pulled in by `pyproject.toml`

## Reporting

Please email **nexaforge.services@gmail.com** with:

- A description of the issue and its impact
- Steps to reproduce (a minimal scope file + command is ideal)
- Affected version / commit hash

Please do not open a public GitHub issue for a security report until we've had a chance to respond and, if
needed, ship a fix. We aim to acknowledge reports within 5 business days.

## Supported versions

HexSwarm is pre-1.0. Security fixes land on `main` and the latest tagged release; older tags are not
separately maintained.
