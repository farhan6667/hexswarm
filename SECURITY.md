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

HexSwarm bounds the dependencies most worth bounding directly in `pyproject.toml` (see `litellm` below) rather
than a full hash-locked `constraints.txt`: a first attempt at a full freeze broke CI across the 3.10-3.12
matrix (one transitive dependency resolved a version with no wheel available for every supported Python), so
it was reverted in favor of targeted bounds that don't fight pip's own resolver. CI runs `pip-audit` on every
push/PR, and a separate nightly workflow (`dependency-audit.yml`) re-runs it on a schedule, so a newly
published advisory against something already installed doesn't go unnoticed just because nobody pushed a
commit that day.

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

**A second, smaller dependency gap found by `pip-audit` itself (2026-10-23/24):** `filelock` 3.32.7, pulled in
transitively by `litellm`, has three known vulnerabilities (CVE-2026-112907, CVE-2026-112913, CVE-2026-112940),
fixed in `filelock` 4.2.1. `litellm` 1.106.2 (the version pinned above) requires `filelock>=3.16.1,<4.0`, and
there is no fixed 3.x `filelock` release, so no single version currently satisfies both "the litellm version
this incident forced us onto" and "patched against these three CVEs." These three CVE IDs are explicitly
ignored in `pip-audit`'s CI and nightly runs, with a comment pointing back here, rather than silently
suppressing the whole scan or leaving CI permanently red for a conflict nobody can resolve by editing
`pyproject.toml`. Revisit (and remove the ignores) once `litellm` raises or drops its `filelock` ceiling.

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
  `10.10.10.*` could be read as `0.0.0.0/0` was checked and did not reproduce.)
- **~~An octet-style wildcard pattern only ever matches hosts under that same prefix~~ — this line was wrong
  and has been removed.** An independent adversarial review found that `10.10.10.*` (and any allow/deny
  pattern ending in an unanchored `*`) matched `10.10.10.evil.com`, not just hosts under `10.10.10.`: the
  glob engine treated `*` as "any characters, including more dots," so nothing stopped it from absorbing an
  entirely different, attacker-chosen domain tacked onto the end. Fixed by matching per dot-label instead of
  via unrestricted globbing (`ScopeGuard._label_glob_match`): a bare `*` now matches exactly one label,
  except as the pattern's first label, which keeps the conventional `*.example.com` "one or more leading
  labels" meaning. See `tests/test_scope_guard.py` for the regression tests.
- **Two CLI fields consumed as trailing positionals, not an option's own argument, could carry an injected
  flag.** `password_brute_force`'s `service` is hydra's final bare argument; a value like `-o/tmp/out` was
  read by hydra as its own `-o` option, not as a service name. Fixed with the same `reject_leading_dash`
  check used elsewhere. `port_scan`'s `ports` and `osint_harvest`'s `sources` are lower risk (each is already
  consumed as the argument to `-p`/`-b`), but are now restricted to the character set a real value can
  contain (so an injected flag can't ride along inside what's supposed to be a plain value either), rather
  than relying on "it's probably fine because of argv position."
- **`metasploit_module_run`'s `extra_options` guard only matched `set RHOSTS`, not `setg` (global set) or any
  other resource-script command.** A `setg RHOSTS <host>` line combined with a fresh `use` line could
  re-target a module after the scope-checked `target` had already set it locally. `extra_options` is now an
  allowlist: every line must be a plain local `set KEY VALUE` (never `setg`, never `use`/`run`/`exploit`/
  anything else), and RHOST/RHOSTS is still rejected specifically within that.
- **The scope guard's host extraction and the wrapped binaries' own URL/host parsers can disagree** on an
  unusual string (backslash-as-slash, a stray percent-encoded byte in a hostname). Checked against this
  project's actual toolset (nuclei/httpx/katana/dnsx/dalfox are Go `net/url`, which doesn't treat `\` as `/`
  or percent-decode a hostname the way some other parsers do) and no live divergence was found, but this is
  a parser-differential class that depends on exactly which binary is wrapped, not something this project
  can close in general. Not fixed; stated here as a limit to keep in mind if a future tool wraps a binary
  with a more permissive URL parser.
- **A file whose contents are scope-checked (`subdomain_takeover`'s subdomain list, `llm_scan`'s REST config)
  is checked, then re-read by the external binary it's handed to**, not re-read atomically or passed as
  already-validated bytes. A local attacker who can race the file between the check and the binary's own
  read (or point the path at something whose content differs per read, like a named pipe) could still get a
  different host scanned than the one the check saw. Requires local file-system access inside the working
  directory already, so the working-directory confinement is still the primary control; not hardened further
  here.
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
