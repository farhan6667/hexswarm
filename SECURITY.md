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

Please do not open a public GitHub issue for a security report until there's been a chance to respond and, if
needed, ship a fix. This is a solo-maintained project: there's no guaranteed response time and no paid bounty,
but reports are taken seriously and acknowledged as soon as possible.

## Supply chain

HexSwarm pins its runtime dependencies in `constraints.txt` (regenerated and reviewed deliberately, not on
every release) and both Dockerfiles install with `pip install -c constraints.txt .`, so a fresh build pulls
exactly the versions that were reviewed, not whatever happens to be newest on PyPI that day. CI runs
`pip-audit` on every push/PR, and a separate nightly workflow (`dependency-audit.yml`) re-checks the pinned
set on a schedule, so a version already on disk getting yanked or newly flagged doesn't go unnoticed just
because nobody pushed a commit that day.

This exists because of a real incident: on 2026-10-21, a malicious `litellm` 1.107.0 was published to PyPI
and Docker Hub/GHCR (a credential stealer plus a second-stage RAT, live roughly 11:39-14:20 UTC; see
[LiteLLM's own incident writeup](https://docs.litellm.ai/blog/security-incident-oct-21-2026)). HexSwarm's
own `pyproject.toml` had `litellm>=1.50.0` with no upper bound and no lock file at the time, so a fresh
install during that window could have pulled it. Checked and found clean: every HexSwarm CI run and
published image build around that date resolved `litellm` outside the compromised window. `litellm` is now
pinned to `>=1.106.2,<1.107`, the version LiteLLM's own advisory names as the last confirmed-clean one.

**If you installed `litellm==1.107.0` yourself** (inside or outside HexSwarm), treat that Python environment
as compromised. Per the vendor's advisory: don't run `pip install` again first (Python startup re-runs the
malicious files); delete `cook.pth`, `cook.py`, `sitecustomize.py` and their `__pycache__` entries from every
affected `site-packages`; kill any process holding `/tmp/remote_code_loader.lock`; then reinstall a pinned
version or, better, rebuild the venv/image from scratch. Rotate every credential that host could reach
(cloud IAM/instance role, API keys, `DATABASE_URL`, any secret in a process environment on that machine).
Uninstalling the package alone does not remove the startup files or stop anything already running.

## Known limits

Honest gaps in what's enforced today, not fixed by this review, stated instead of implied away:

- **DNS is not resolved for scope checking.** The scope guard matches a target's host *name* (or literal
  IP) against the allow/deny list; it does not resolve a hostname and check the IP(s) it actually points at.
  An allowed name that later (or already) resolves to a denied or out-of-scope IP is not caught. Implementing
  this safely needs a resolve-then-check step wired into every network-touching adapter, which hasn't been
  built yet.
- **Redirects are only blocked on `prompt_injection_probe`'s own request**, which disables `requests`'
  default redirect-following so an in-scope endpoint can't bounce it to an out-of-scope host via a 3xx. Other
  tools here shell out to external binaries (`nuclei`, `gobuster`, `sqlmap`, `dalfox`, ...) that make their
  own HTTP requests and follow redirects by their own logic, outside HexSwarm's control; whether a given
  binary can be configured not to follow redirects is a per-tool, per-binary question not addressed here.
- **Overly broad scope entries are trusted as written.** `ScopeGuard`'s own docstring says the scope file is
  "the single source of truth": an operator who writes `0.0.0.0/0` into `allow` gets exactly that. Nothing
  here second-guesses a CIDR the operator chose on purpose. (A specific claim that a narrower entry like
  `10.10.10.*` could be read as `0.0.0.0/0` was checked and did not reproduce: an octet-style wildcard
  pattern only ever matches hosts under that same prefix.)
- **Tool output is not currently labeled as untrusted data when it reaches the model.** A hostile target
  could try prompt injection through whatever text a scanner returns, aiming at the agent's next tool
  choice. What already holds regardless: every tool call, however the agent decided to make it, still goes
  through the same `ScopeGuard`/`Tool.run()` gate described in this policy, so injected text can influence
  *what the agent asks for* but can't skip authorization for it. Clearly delimiting tool output as untrusted
  in the prompts/report formatting themselves is a presentation-layer improvement that hasn't been made yet.
- **The toolchain sandbox image is pulled by tag (`:latest`), not by digest**, and defaults to host mode
  (`HEXSWARM_SANDBOX=host`) with a single pre-run confirmation rather than per-tool-call confirmation
  (`HEXSWARM_HITL=false` by default). Pin `HEXSWARM_SANDBOX_IMAGE` to a specific digest
  (`ghcr.io/farhan6667/hexswarm-toolchain@sha256:...`, from `docker buildx imagetools inspect
  ghcr.io/farhan6667/hexswarm-toolchain:latest`) if you want to be sure which exact image you're running
  instead of whatever `latest` currently points at. Flipping either default is a real behavior change for
  existing scripted/CI usage, so it hasn't been done without a maintainer decision on it.

## Supported versions

Security fixes land on `main` and the latest tagged release; older tags are not separately maintained.
