# Changelog

All notable changes to HexSwarm are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [1.1.1] - 2026-10-24

A same-day QA pass on 1.1.0 itself: a fresh independent adversarial review (not the outside
reviewer; a separate review run given only the diff and a threat list) found that 1.1.0's own
scope-matching code had a real bypass, and this release fixes it, along with three smaller
findings from the same pass, and ships the process changes meant to catch this class of thing
automatically from now on.

### Security
- **A real scope bypass: any allow/deny glob ending in an unanchored `*` admitted an
  attacker-chosen suffix.** `10.10.10.*` (written to mean "any value in this one octet") also
  matched `10.10.10.evil.com`, because the glob engine's `*` crosses dot boundaries with nothing
  anchoring the end. SECURITY.md had actively (and wrongly) claimed the opposite. Fixed by
  matching per dot-label instead of raw glob (`ScopeGuard._label_glob_match`): a bare `*` now
  matches exactly one label, except as the pattern's first label, which keeps the conventional
  `*.example.com` meaning. The previously-shipped test for this exact claim only checked that an
  in-scope host was admitted and an unrelated one rejected; it never tried a hostname that
  *extends* the prefix, so it passed while the bypass was open. Strengthened, and the fuzz
  suite's allow list now includes a trailing-wildcard pattern so this shape gets exercised going
  forward.
- `password_brute_force`'s `service` field (a trailing positional, not consumed as another
  option's argument) could carry an injected hydra flag; now dash-rejected like `target`/
  `ssh_user`. `port_scan`'s `ports` and `osint_harvest`'s `sources` are lower risk (already
  consumed as `-p`/`-b`'s own argument) but are now restricted to the character set a real value
  can contain.
- `metasploit_module_run`'s `extra_options` guard only blocked `set RHOSTS`, not `setg` (global
  set) or a smuggled `use` line that re-enters module context where a global RHOSTS could still
  apply. `extra_options` is now an allowlist: only plain local `set KEY VALUE` lines, never
  `setg` or any other resource-script command.
- Documented two lower-severity findings in SECURITY.md rather than fixing them this round: a
  URL-parser differential between the scope guard and the wrapped binaries (checked against this
  project's actual toolset, no live divergence found), and a TOCTOU gap where a scope-checked
  file's contents are re-read by the external binary rather than passed as already-validated
  bytes.
- `pip-audit` correctly flagged a `filelock` CVE (pulled in transitively by `litellm`); no fix is
  currently possible without conflicting with `litellm`'s own version ceiling, so it's
  ignored by CVE ID with a comment explaining why, documented in SECURITY.md, not silently
  suppressed.

### Process
- `ci.yml` now runs on every push to every branch, not just `main`/PRs: the direct cause of why
  1.1.0's dependency-pinning mistake (see below) reached `main` at all was that it had never run
  on its own branch first. Matrix widened to Python 3.10-3.14.
- New `tests/test_tool_parameter_coverage.py`: every registered tool and every parameter it
  accepts must be classified (host/host-in-file/path/ssh_user/free_text/safe); fails if a new
  tool or parameter ships unclassified.
- New `tests/test_scope_guard_fuzz.py`: hypothesis-based fuzz tests on the scope matcher, dash
  rejection and path confinement.
- New `docs/process-notes/2026-10-security-reviews-root-cause.md` and `PRE_RELEASE_CHECKLIST.md`.
- `Dockerfile.toolchain`'s `apt-get` now retries with backoff: a flaky Kali mirror
  (mirror.us.cdn-perfprod.com, a GeoIP redirect behind http.kali.org) caused real, reproducible
  CI failures in the 1.1.0 toolchain-image and lab-validation workflows.
- Fixed stale version drift: `CITATION.cff` still said 1.0.1, README's test count said 197 (now
  246).

## [1.1.0] - 2026-10-23

Two more rounds of reports from the same external reviewer, Allen Clark, thank you. The
table below is what was checked, what turned out real, and what was fixed.

| # | Reviewer's point | Real? | Fixed? |
|---|---|---|---|
| 1 | IP wildcard (`10.10.10.*`) also matches `0.0.0.0/0` | Checked, did not reproduce | No code change; see "Known limits" in SECURITY.md |
| 2 | Some tools skip the scope gate completely (subdomain takeover, garak, exploit search, CTF tools, some MCP tools) | Partly real | `subdomain_takeover` and `llm_scan` now scope-check every host found inside their staged file/config, where the real network destinations actually live. `exploit_search` and the CTF tools were already correctly exempt by design (their "target" is a local DB query string or a local file's own bytes, never a network host); kept as-is |
| 2b | MCP tools whose host argument is named `url` or `host` instead of `target` go unchecked | Real | `RemoteMCPTool` now checks `target`/`url`/`host`/`hostname` (configurable via a new `host_fields` map), and fails closed with a clear error if none is present on a scope-checked tool |
| 3a | Hostnames aren't resolved, so an allowed name pointing at a denied IP gets through | Real limitation | Not implemented; stated plainly in SECURITY.md rather than silently left uncovered |
| 3b | `prompt_injection_probe` follows redirects, which could bounce it out of scope | Real | That one `requests.post` call now passes `allow_redirects=False` |
| 4 | Nothing stops a target (or `ssh_user`) starting with `-`, which a CLI tool could read as an option | Real | New `reject_leading_dash()` check in `Tool.run()` (every tool's `target`) and in `linux_privesc_enum` (`ssh_user`) |
| 5 | Wordlist/userlist/passlist paths and the CTF file tools can read any local file | Real | New `hexswarm.safety.paths.confine_path()`: every such path is resolved and must stay inside a working directory (`HEXSWARM_WORK_DIR`, defaults to cwd); applied to `file_identify`, `string_extract`, `binwalk_scan`, `directory_brute`'s `wordlist`, and `password_brute_force`'s `userlist`/`passlist` |
| 6a | The sandbox toolchain image is pulled as `:latest`, not pinned by digest | Real | Documented how to pin `HEXSWARM_SANDBOX_IMAGE` to a digest in SECURITY.md; not hardcoded here since the current digest needs the user's own verification, not a guess |
| 6b | Defaults are host mode with no per-step confirmation | Real, but a UX decision | Not flipped: changing either default silently would break existing scripted/CI usage. Documented as a known limit; left for a maintainer decision rather than changed unilaterally |
| 7 | Raw tool output goes straight back to the model, a hostile target could try prompt injection toward these gaps | Real, structural | What already held and still holds: every tool call still goes through the same `ScopeGuard`/`Tool.run()` gate regardless of what prompted the agent to request it, so injected text can influence what's asked for, never skip authorization for it. Labeling tool output as untrusted in the prompt/report layer itself is not done; stated as a limit |

Also bundled in this release: the dependency pinning prepared for 1.0.3 below (not shipped
separately; see the note there).

### Security
- New `hexswarm.safety.paths` module (`confine_path`) and `reject_leading_dash()` in
  `tools/base.py`, both described in the table above.
- `subdomain_takeover` and `llm_scan` read their staged file/config and scope-check every
  host found inside it before running, instead of only checking `target` (a file path for
  the former, a model-name label for the latter, neither a network host itself).
- `RemoteMCPTool` checks `target`/`url`/`host`/`hostname` (configurable per tool via a new
  `host_fields` map in the MCP server config), fails closed when none is present.
- `prompt_injection_probe` disables HTTP redirects on its own request.
- New test file `tests/test_security_hardening.py` plus additions to `tests/test_mcp_client.py`
  for all of the above. 229 tests pass, ruff and mypy clean.

## [1.0.3] - 2026-10-23 (prepared, not shipped separately; folded into 1.1.0 above)

Kept as its own entry for the record, since this is the dependency-pinning work from the
earlier LiteLLM supply-chain report, done first and then released together with 1.1.0
rather than as its own tag. If a separate 1.0.3 tag is wanted instead, split this out.

### Security
- `litellm` bound to `>=1.106.2,<1.107` (was `>=1.50.0`, no upper bound) after the
  2026-10-21 PyPI/Docker supply-chain compromise of `litellm` 1.107.0. See the "Supply
  chain" section of SECURITY.md for the incident, what was checked, and what to do if you
  installed the compromised version yourself.
- New nightly workflow `dependency-audit.yml`: re-runs `pip-audit` on a schedule, so a
  newly published advisory doesn't require a push to notice.
- A full hash-locked `constraints.txt` was tried first and reverted within this same
  release: it was generated from one Python 3.14 environment and broke every other
  supported version (3.10-3.12) once pushed, because a transitive pin (`pydantic-settings
  ==2.16.1`) had no matching wheel there. CI, the toolchain image build, and the
  lab-validation workflow all failed on the first push of this release; caught within the
  hour, `constraints.txt` removed, both Dockerfiles and CI reverted to a plain
  `pip install .` the same day. The `litellm` bound in `pyproject.toml` is the actual fix
  for the incident and was unaffected throughout.

## [1.0.2] - 2026-10-23

### Security
- **Scope bypass: a target with no URL scheme was glob-matched unparsed.** An allow rule written
  as a domain glob (e.g. `*.lab.local`) matched a crafted value such as `evil.com/?x.lab.local`,
  because the glob's leading `*` matched straight across the `/`, `?` and everything else up to
  the real suffix. Fixed by always parsing a target into its host component before matching
  (with or without a scheme), and failing closed when no clean host can be extracted. Reported by
  Allen Clark; thank you.
- **`metasploit_module_run`'s `extra_options` could redefine RHOSTS/RHOST.** The scope guard only
  ever authorized the `target` field; a call could pass scope on an in-scope `target` and still
  set a different host through `extra_options`, since `msfconsole` uses whichever `set RHOSTS`
  line ran last in the resource script. `extra_options` now rejects any line that sets
  RHOST/RHOSTS; that value only ever comes from `target`, the one the scope guard checks.
  Also reported by Allen Clark.
- Added a hostile test suite for both issues, plus related edge cases (ports, trailing dots,
  case, bare IPv6 literals, userinfo-style targets) that the fix also had to get right without
  reopening either bug.

### Changed
- The Kali-based toolchain image now also installs amass and dalfox, so the new subdomain_enum and
  xss_scan adapters run for real inside the sandbox instead of dropping to simulate mode. theHarvester,
  SubOver, and garak stay out of the image (theHarvester's apt package pulls a system Python dependency
  that conflicts with the in-image install; SubOver is a Go build and garak a heavy pip install) and
  still simulate there.

## [1.0.1] - 2026-10-13

### Added
- A branded CLI banner (the HexSwarm wordmark, version, and the NexaForge / SFA line) shown at the
  top of `version`, `doctor`, `run`, and `ctf`, plus a consistent cyan theme on the tool and playbook
  tables, so the terminal output looks like a finished product rather than raw prints.
- Five new tool adapters wrapping well-known open-source scanners, each scope-gated and risk-tiered
  like the rest: `subdomain_enum` (OWASP Amass, passive subdomain and attack-surface enumeration),
  `osint_harvest` (theHarvester, passive email/name/host OSINT), `subdomain_takeover` (SubOver,
  dangling-DNS takeover checks over a staged subdomain list), `xss_scan` (dalfox, focused XSS and
  parameter analysis), and `llm_scan` (garak, a full LLM vulnerability scanner for the ai-security
  track, deeper than the built-in prompt_injection_probe). Each wraps the tool's own CLI; nothing is
  vendored, so a missing binary just drops to simulate mode as usual.

### Fixed
- Compliance mapping routing. Two keyword collisions surfaced by validation are fixed: a
  scanner naming "rce" in its output no longer routes to the exploitation-foothold control
  set (the foothold and privilege-escalation rules are now pinned to the exploit and privesc
  phases, so a scan-phase detection maps to the vulnerability rules instead), and the generic
  word "flagged" no longer pulls a finding into the AI prompt-injection rule. Added a
  `match_phases` gate to the rule engine and regression tests for both cases.

## [1.0.0] - 2026-10-11

First stable release. The alpha label is dropped because the pipeline is now validated
end to end in CI against a live, genuinely vulnerable application, not just in simulate
mode and unit tests.

### Added
- Compliance mapping (`hexswarm compliance --findings <json> --framework iso27001|pci-dss|all`):
  takes a run's findings and, for each one, points at the ISO 27001:2022 Annex A controls and
  PCI DSS 4.0 requirements it relates to. It is advisory, not a verdict. A mapping means "this
  finding touches that control", never "you pass" or "you fail", an unmapped finding is not
  "compliant" (only unmatched), and every output carries that disclaimer. It maps technical
  findings only; governance and policy controls a pentest never touches are out of scope by design.
- A `lab-validation` CI workflow that spins up a disposable OWASP Juice Shop, runs the real web
  toolchain (httpx, whatweb, nuclei, gobuster, sqlmap) against it through the real tool registry,
  and maps the findings through the compliance layer. This is the end-to-end "validated against a
  real target" gate. The tool-level run is deterministic and needs no API key; a full LLM-driven
  run is an extra step that fires only when a model key is set as a repo secret.

### Changed
- Status moved from alpha to stable. Validation caught and fixed one real mapping misroute (a
  network-exposure finding routing to the web rule on a keyword tie) before release.

## [0.2.0] - 2026-10-11

### Added
- MCP (Model Context Protocol) support, both directions: `hexswarm mcp-server` exposes the
  whole tool registry over stdio MCP to any client (Claude Desktop, Claude Code, Kali's
  native MCP workflow), scope-gated exactly like every other entry point; `hexswarm.mcp.client`
  lets an agent pull in tools from external MCP servers via a small YAML config, each one
  still duck-typed as a HexSwarm `Tool` so it goes through the same scope/risk gating. Verified
  end to end against a real subprocess round trip in both directions, not just unit tests.
- Per-tool Docker sandboxing (`HEXSWARM_SANDBOX=docker`): each tool call runs in its own
  disposable `docker run --rm`, isolated from the host, from HexSwarm itself, and from every
  other tool call in the run, a materially different posture than the whole app merely
  running inside a Dockerfile.
- `Dockerfile.toolchain`: a Kali-based image with the real pentest toolchain installed, built
  and smoke-tested by a dedicated CI workflow that asserts a real `port_scan` against
  scanme.nmap.org comes back `simulated=False`. This is `HEXSWARM_SANDBOX_IMAGE`'s default.
- `hexswarm bench`: runs the CTF agent against a small CTF-style challenge set bundled inside
  the package (works from a plain `pip install`, not just a clone), reporting a pass count in
  the spirit of Cybench/NYU-CTF Bench but tiny and fully offline.
- Threshold human-in-the-loop (`run --confirm-from <tier>`): pause for confirmation only at a
  given risk tier and above (e.g. let recon/scan run, confirm before exploit/privesc), instead
  of the all-or-nothing HITL switch.
- `run --mcp-config <file>`: pull tools from external MCP servers into an engagement, each one
  scope-gated and risk-tiered like a built-in tool.
- New `ai-security` tool category: `prompt_injection_probe` sends a battery of known
  injection/system-prompt-leak payloads to a target chat/LLM HTTP endpoint and flags
  responses matching compliance heuristics (triage, not a confirmed-vulnerability claim).
  Exposed via `hexswarm ai-audit --target <url> --scope <file>`.
- Knowledge base: per-service aliases (ssh now matches "openssh"/"libssh" banners, not just
  the literal word) and alias-match-count ranking instead of unordered substring containment,
  plus ten new services (postgresql, redis, mongodb, elasticsearch, jenkins, docker/kubernetes
  APIs, telnet, vnc, snmp, wordpress).
- Cost/token budget governance and an engagement trace: `run --max-cost`/`--max-tokens` put a
  hard ceiling on an autonomous run and abort it the moment it's crossed; `--trace-out` writes
  an append-only JSONL of every LLM call and tool call with tokens, cost, phase, timing, and
  whether a tool was simulated. Both opt-in. This is the spend-control/observability gap the
  2026 agentic-pentest field mostly leaves open.
- Evidence trail on every finding: the exact command that produced it, whether it was a real
  run or simulate mode, and a sha256 of the full output, so a finding can be traced to a
  reproducible command and confirmed not to be a dry run before it's cited.
- SARIF 2.1.0 and structured-JSON export (`run --sarif-out`), so findings drop straight into
  GitHub's code-scanning / Security tab or a CI gate.
- Verification pass (`run --verify`): an optional second-opinion agent that reviews each
  medium+ finding against its evidence and flags likely false positives (and never lets a
  simulated result read as confirmed) before the report.
- Engagement playbooks: `run --playbook recon-only|web-assessment|full-engagement` (or a path)
  bundle goal + phase order + a risk cap. A playbook can only narrow the scope file's risk cap,
  never widen it, and carries no scope or target of its own. `hexswarm playbooks` lists them.
- ProjectDiscovery recon tools: http_probe (httpx), fast_port_scan (naabu), web_crawl (katana),
  dns_resolve (dnsx), wired as scope-gated adapters like the rest.
- Bundled vulnerable labs: `hexswarm lab list|up|down` spins up a disposable, localhost-only
  OWASP Juice Shop (with a ready-made scope file) so the real pipeline can be validated against
  a genuinely vulnerable app without touching anyone else's systems.

## [0.1.0] - 2026-10-10

Initial public release: scope-gated recon -> scan -> exploit -> privesc -> report pipeline,
LiteLLM-based model routing, safe-adapter tool layer with simulate mode, CLI, test suite.

### Added
- `hexswarm init`: an interactive setup wizard that writes a working `.env` and `scope.yaml`
  from a few guided questions (model choice, in-scope targets, max risk level), instead of
  requiring a new user to hand-edit `.env.example`/`scope.example.yaml` and already know
  HexSwarm's config keys and risk-level vocabulary.
- `hexswarm doctor`: checks whether the configured model is actually reachable (Ollama
  running? API key set for a cloud provider?) and how many of the built-in tools are
  installed, so a missing piece is caught before a long `run` does.
- Live per-phase progress during `run`/`ctf` (a status line while each agent is working, a
  "done" line per phase) instead of the terminal going silent until the whole thing finishes.
- `run`/`ctf` output is now rendered as proper Markdown in bordered panels (one per phase,
  one for the final report) instead of a dump of raw text, matching what the report agent
  was already asked to write.
- `Orchestrator(progress_callback=...)` hook so any caller, not just the bundled CLI, can
  observe phase start/done events.
- Standalone CTF-solving agent and `hexswarm ctf` command: file identification, string
  extraction, binwalk-style embedded-file scanning, hash identification, and a pure-Python
  multi-codec decoder (base64/base32/hex/URL/ROT13/binary), none of which touch the
  network-scope guard since they operate on local files/strings.
- `Tool.local_only` execution path for pure-Python tools that never shell out to a binary.
- `Tool.category` ("pentest" vs "ctf") so the tool registry can serve two separate agent
  tracks from one codebase.
- Finding severity is now inferred from a tool's risk tier and outcome instead of always
  being hardcoded to "info", so `FindingsStore.by_severity()` is actually meaningful.
- `--yes`/`-y` flag and a one-time pre-run authorization confirmation on `hexswarm run`.
- `Dockerfile` for running HexSwarm in an isolated container.
- `pip-audit` and `mypy` added to CI, alongside the existing ruff + pytest + bandit checks.

### Fixed
- `exploit_search`'s "target" is a product/version search string, not a network address; it
  was being forced through the host-scope check and would have rejected every real call.
  Tools now declare `requires_scope_check = False` when their target isn't a network host.
- `ScopeGuard` now extracts the hostname from URL-style targets before matching, so scope
  entries written as domains actually match the full URLs that `web_vuln_scan`,
  `directory_brute`, `sql_injection_scan`, and `http_fingerprint` pass as their target.
  Previously those four tools could never satisfy a domain-based allow rule.
- `linux_privesc_enum` downloaded and piped linpeas.sh straight from GitHub into `bash` on
  the target at runtime. It now expects an operator-staged, pre-vetted script path instead,
  and no longer scope-checks "user@host" (which could never match a plain-host allow rule).
- `windows_privesc_enum`'s `binary` ClassVar didn't match what was actually executed
  (`pwsh`, not `winpeas.exe`), so `is_available()` always reported it as missing even when
  PowerShell remoting was fully usable. Also fixed: the target value was being interpolated
  unescaped into a PowerShell `-Command` string, letting a single quote in the target break
  out and run arbitrary PowerShell locally, before any remote connection was made.
- `metasploit_module_run` now rejects a newline smuggled into `module` or `target`, which
  could otherwise inject extra, unintended lines into the generated msfconsole resource
  script.
