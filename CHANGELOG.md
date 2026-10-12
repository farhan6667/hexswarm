# Changelog

All notable changes to HexSwarm are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
