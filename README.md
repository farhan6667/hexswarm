<h1 align="center"><img src="docs/img/banner.webp" alt="HexSwarm: a scope-gated swarm of AI agents for authorized penetration testing and CTF challenges" width="100%"></h1>

<p align="center">
  <a href="https://github.com/farhan6667/hexswarm/actions/workflows/ci.yml"><img src="https://github.com/farhan6667/hexswarm/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-3776ab.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/models-OpenAI%20%7C%20Anthropic%20%7C%20Ollama%20%7C%20100%2B-5fd9a4.svg" alt="Any LiteLLM-supported model">
  <img src="https://img.shields.io/badge/status-alpha-ff8a00.svg" alt="Status: alpha">
</p>

**HexSwarm is an open source Python framework for running AI agents against authorized penetration testing, bug bounty, and CTF targets.** Independent project by Syed Farhan Ahmed (SFA) at NexaForge. It wraps publicly available security tools (nmap, Nuclei, gobuster, sqlmap, Hydra, Metasploit, searchsploit, and others) via their own CLIs; it is not affiliated with, sponsored by, or endorsed by any of their maintainers or vendors.

It connects to OpenAI, Anthropic, local Ollama models, or 100+ other providers through one interface, and gives those agents a scoped,
safety-gated library of real offensive-security tools (recon, vulnerability scanning, exploitation, and privilege escalation), so a single
high-level goal like "find a web server on this target and check for common vulnerabilities" turns into a coordinated, auditable swarm run.

## At a glance

| | |
|---|---|
| **Runs** | `recon -> scan -> exploit -> privesc -> report`, a five-agent pipeline against one authorized target per engagement |
| **Gates** | Every tool call against an explicit `scope.yaml` allow/deny list and a max risk tier, enforced in code beneath the LLM, not in its prompt |
| **Connects to** | OpenAI, Anthropic, local Ollama, or 100+ other providers through [LiteLLM](https://github.com/BerriAI/litellm), one config line to switch |
| **Also solves** | CTF challenges: file ID, string extraction, embedded-data scanning, hash ID, and multi-codec decoding, no scope file needed |
| **Onboards with** | `hexswarm init` (guided setup wizard) and `hexswarm doctor` (checks your model and tools are actually ready) |
| **Never fakes** | A missing tool binary runs in clearly labeled simulate mode instead of crashing or silently skipping |
| **Status** | Alpha. 76 automated tests, ruff/mypy/bandit clean, independently audited; not yet battle-tested against a live engagement |

## Screenshots

**`hexswarm init`**, the guided setup wizard:

<p align="center"><img src="docs/screenshots/hexswarm_init.png" alt="hexswarm init interactive wizard choosing a model, naming the engagement, adding scanme.nmap.org to scope, and picking a risk level" width="700"></p>

**`hexswarm doctor`**, checking the configured model and tool availability:

<p align="center"><img src="docs/screenshots/hexswarm_doctor.png" alt="hexswarm doctor reporting the Anthropic API key is set, 7 of 17 tools installed, and the engagement is ready to run" width="700"></p>

**`hexswarm tools`**, the full registry with risk tiers color-coded:

<p align="center"><img src="docs/screenshots/hexswarm_tools.png" alt="hexswarm tools output listing all 17 registered tools with category, risk level, binary, and install status, color-coded by risk" width="700"></p>

**`hexswarm run`**, a real recon pass against scanme.nmap.org through the full phase pipeline, each phase's output and the final report rendered as Markdown panels:

<p align="center"><img src="docs/screenshots/hexswarm_run.png" alt="hexswarm run showing recon, scan, exploit, and privesc phase panels followed by the final Markdown assessment report" width="700"></p>

**`hexswarm ctf`**, identifying and decoding a challenge file end to end:

<p align="center"><img src="docs/screenshots/hexswarm_ctf.png" alt="hexswarm ctf identifying a file as ASCII text and decoding its Base64 content to recover the flag" width="700"></p>

<details>
<summary>hexswarm scope-check and --help</summary>

<p align="center"><img src="docs/screenshots/hexswarm_scope_check.png" alt="hexswarm scope-check showing an authorized target accepted and an out-of-scope target rejected" width="700"></p>

<p align="center"><img src="docs/screenshots/hexswarm_help.png" alt="hexswarm --help output listing the version, tools, scope-check, run, and ctf commands" width="700"></p>

</details>

## Why HexSwarm exists

Most "AI pentesting" demos are a single agent in a loop with a handful of hardcoded shell calls. That's fine for a conference talk and useless for
real engagement work, because nobody can tell what it's allowed to touch, what model it's trusting its judgment to, or what it actually ran.

HexSwarm is built around three non-negotiables instead:

- **Scope is law.** Every single tool call, recon, scan, exploit, or privesc, is checked against a scope file before it runs. No scope file, no run.
  An agent cannot "accidentally" touch something outside the engagement, because the scope guard sits underneath the LLM, not inside its prompt.
- **You pick the brain.** Swap OpenAI for Anthropic for a local Ollama model with one config line, no code changes, no vendor lock-in. Run a cheap
  local model for recon and a stronger cloud model for exploit reasoning in the same run if you want.
- **Every finding is attributable.** HexSwarm never silently fakes output. If a tool's binary isn't installed on the host, it says so and returns a
  clearly labeled simulated result instead of guessing, so you always know whether a finding came from a real scan or a dry run.

None of that should cost you a rough setup experience: `hexswarm init` writes your config and scope file for you, `hexswarm doctor` tells you what's
missing before a run does, and `run`/`ctf` show a live status line per phase instead of going silent, then print each phase's output and the final
report as properly rendered Markdown panels, not a wall of raw text.

## How it works

HexSwarm runs a linear swarm of five specialized agents, each scoped to only the tools appropriate for its phase:

```
  Recon  ───▶  Vulnerability Scan  ───▶  Exploit  ───▶  Privilege Escalation  ───▶  Report
(read-only +   (nuclei, gobuster,      (searchsploit,    (post-exploitation            (Markdown
 active recon:  sqlmap, hydra)          Metasploit)        enumeration only,             findings
 whois, DNS,                                                after a foothold             report)
 nmap, whatweb)                                             already exists)
```

Findings accumulate in a shared store as the swarm progresses, so the exploit agent sees what recon actually found instead of guessing, and the
report agent writes up the whole engagement at the end, honestly noting which results were real tool runs and which were simulated.

```bash
hexswarm run \
  --goal "find a web server on this target and check for common vulnerabilities" \
  --target scanme.nmap.org \
  --scope examples/scope.example.yaml
```

Before anything runs, HexSwarm shows the engagement name, target, who authorized it, and the max risk level from your scope file, and asks you
to confirm once. Pass `--yes` to skip that prompt for CI or scripted use.

### CTF mode

CTF challenges aren't network targets, so they get their own agent and command, no scope file needed:

```bash
hexswarm ctf --goal "find the flag in this binary" --file ./challenge.bin
```

The CTF agent identifies the file type, pulls printable strings, checks for embedded data, and tries common encodings (Base64/Base32/hex/
URL/ROT13/binary) on anything that looks encoded, chaining its own tool outputs together until it finds a flag or runs out of obvious angles.

### AI/LLM application testing

An AI-native framework testing other AI-native applications is a natural fit, and AI-in-scope bug bounty programs grew 270% in HackerOne's
2025 data. This probes a target chat/LLM HTTP endpoint for prompt-injection and system-prompt-leak weaknesses, same scope-file requirement as `run`:

```bash
hexswarm ai-audit --target https://app.example.com/api/chat --scope scope.yaml
```

A flagged response is a text-pattern heuristic hit, worth a human reading the actual reply, not a confirmed vulnerability. Read it the same
way you'd read any other scanner's output here.

### MCP: use HexSwarm's tools from any MCP client, or pull in someone else's

[MCP](https://modelcontextprotocol.io/) is where AI-driven security tooling is heading in 2026: Kali Linux now ships a native MCP-based Claude
workflow, and projects like PentestMCP expose pentest tooling the same way. HexSwarm speaks MCP in both directions.

Expose every HexSwarm tool to Claude Desktop, Claude Code, or any other MCP client:

```bash
hexswarm mcp-server --scope scope.yaml
```

Every call still goes through the exact same `ScopeGuard` as the CLI and the built-in agents: MCP is a different transport for the same
gated tool registry, not a looser path around it.

Pull tools from someone else's MCP server into a HexSwarm agent, via a small YAML config (see
[`examples/mcp_servers.example.yaml`](examples/mcp_servers.example.yaml)):

```yaml
servers:
  - name: pentestmcp
    command: python
    args: ["-m", "pentestmcp"]
    risk_level: "exploit"
```

HexSwarm doesn't know what an arbitrary external tool actually does, so you declare the risk tier (and, per tool, whether its target is even
a network host) when you add the server, the same trust decision as adding any new tool.

### Sandboxing each tool call in its own container

By default every tool runs as a plain subprocess on the host, same as always. Setting `HEXSWARM_SANDBOX=docker` switches every tool call to
run inside its own disposable `docker run --rm` instead: one fresh container per call, isolated from the host, from HexSwarm itself, and from
every other tool call in the run. That's a meaningfully different safety posture than "the whole app happens to run inside a Dockerfile."

```bash
HEXSWARM_SANDBOX=docker HEXSWARM_SANDBOX_IMAGE=ghcr.io/farhan6667/hexswarm-toolchain:latest hexswarm run ...
```

`ghcr.io/farhan6667/hexswarm-toolchain` (built from [`Dockerfile.toolchain`](Dockerfile.toolchain)) is a Kali-based image with the real
toolchain installed: `hexswarm tools` reports every binary as actually present when run inside it, not simulate mode.

### Benchmarking a model/version

```bash
hexswarm bench
```

Runs the CTF agent against a small local CTF-style challenge set ([`examples/benchmarks/`](examples/benchmarks/)) and reports a pass count,
in the spirit of Cybench/NYU-CTF Bench but tiny and fully offline: "solved 5/6" is a number anyone can reproduce by cloning the repo and
running the same command against the same challenges, not a vibe.

## Install

```bash
git clone https://github.com/farhan6667/hexswarm.git
cd hexswarm
pip install -e .
hexswarm init
```

`hexswarm init` is a guided setup wizard: it asks which model to use (a local Ollama model needs no API key at all), what's in scope, and how
aggressive the engagement is allowed to get, then writes a working `.env` and `scope.yaml` for you. No hand-editing YAML or memorizing the
risk-level vocabulary. It ends by printing the exact `hexswarm run` command for what you just configured.

Before pointing it at a real target, run:

```bash
hexswarm doctor
```

It checks that your configured model is actually reachable (starts Ollama? has an API key set?) and reports how many of the built-in
tools are installed on this machine, so you find out about a missing piece before a 20-minute engagement run does.

HexSwarm itself has no heavy dependencies, it's a thin orchestration layer. The underlying security tools (`nmap`, `nuclei`, `gobuster`,
`sqlmap`, `hydra`, `searchsploit`, Metasploit, plus `file`/`strings`/`binwalk`/`hashid` for CTF mode) are expected to live on a proper pentest
host (Kali, a security-focused Linux box, or WSL). If a binary isn't present, the matching tool runs in simulate mode automatically, so the
framework and its test suite work anywhere Python runs.

Prefer a container to a bare host? `docker build -t hexswarm .` gives HexSwarm an isolated place to run. The default image doesn't bundle the
pentest toolchain (see the comment at the top of the [Dockerfile](Dockerfile) for how to layer it on top of a Kali base image), so out of the
box it runs the same way a plain dev machine does: real logic, simulated tool output.

## Configure a model

Copy `.env.example` to `.env` and set one model string:

```bash
# Local, free, private
HEXSWARM_PRIMARY_MODEL=ollama/llama3.1

# Or a hosted model
HEXSWARM_PRIMARY_MODEL=anthropic/claude-sonnet-5
HEXSWARM_FALLBACK_MODELS=openai/gpt-4o
```

Model routing goes through [LiteLLM](https://github.com/BerriAI/litellm), so any provider string it recognizes works here without touching
HexSwarm's code.

## Define your scope before you run anything

```yaml
engagement_name: "example-lab-ctf"
allow:
  - "10.10.10.0/24"
  - "scanme.nmap.org"
deny:
  - "10.10.10.1"
max_risk_level: "intrusive"   # read_only | active_recon | intrusive | exploit | post_exploit
authorized_by: "Your Name / engagement letter reference"
```

Validate it on its own before a real run:

```bash
hexswarm scope-check examples/scope.example.yaml scanme.nmap.org
```

## Extending HexSwarm

Adding a tool is a small, self-contained class:

```python
from hexswarm.tools.base import Tool, ToolRegistry
from hexswarm.safety.guard import ToolRiskLevel

class MyScanner(Tool):
    name = "my_scanner"
    description = "What this tool does and when an agent should reach for it."
    binary = "my-scanner-cli"
    risk_level = ToolRiskLevel.INTRUSIVE

    def build_command(self, **kwargs):
        return [self.binary, "--target", kwargs["target"]]

ToolRegistry.register(MyScanner())
```

It's picked up automatically by whichever phase agent matches its `risk_level`, no orchestrator changes needed. Set `category = "ctf"` instead
of the default `"pentest"` if it belongs to the CTF agent rather than the network pipeline, and `requires_scope_check = False` if its `target`
is a local file path or search string rather than an actual network host (the scope guard would otherwise reject every call, since a file path
can never match a host/CIDR/domain allow rule).

## Frequently asked questions

**Is this safe to point at a random website?**
No. HexSwarm refuses to run without an explicit scope file, and every tool call is checked against it, but that only enforces *your* intent. It
doesn't make a target legal to test. Only run HexSwarm against systems you own or are explicitly authorized to test (your own lab, a CTF, a
bug bounty program's in-scope assets, or a signed engagement).

**Does it work without an internet connection or API key?**
Yes, if you point `HEXSWARM_PRIMARY_MODEL` at a local Ollama model. No cloud calls, no API key, no cost.

**What happens if `nmap`/`sqlmap`/etc. aren't installed?**
The matching tool runs in simulate mode: it reports that the binary is missing and shows the exact command it would have run, instead of
crashing or silently skipping. Install the real toolchain on a Linux/Kali/WSL host for live results.

**Is "fully autonomous by default" actually safe?**
Autonomy only applies to deciding *which* authorized action to take next, not to *what's* authorized. The scope guard and the per-phase tool
boundaries are enforced in code beneath the LLM, not as a prompt instruction, and they apply identically whether human-in-the-loop confirmation
is switched on or off. HITL is an optional extra layer for anyone who wants per-step confirmation on top of that.

**How is this different from running ChatGPT in a terminal?**
Five things: a scope guard that physically blocks out-of-scope tool calls, a phase-based tool allowlist (the exploit agent literally cannot call
privesc tools), a shared findings store so agents build on each other's work instead of starting from a blank context, provider-agnostic model
routing with automatic fallback, and simulate-mode tooling that keeps the whole pipeline testable without a live target.

**Does CTF mode need a scope file too?**
No. CTF tools analyze a local file or a raw string you already have, there's no network host to authorize, so `hexswarm ctf` doesn't take a
`--scope` argument at all. The network-pentest pipeline (`hexswarm run`) still always requires one.

## Contribute

This project is free and built in the open. The most useful things you can send:

- a **compatibility report** from a real pentest host (Kali, a hardened Linux box, WSL) with the full toolchain installed, since most of this
  was built and tested in simulate mode,
- a **new tool adapter** for something not wrapped yet (see [Extending HexSwarm](#extending-hexswarm) above),
- a fix, a test, or a clearer sentence in the docs.

Start with a [good first issue](https://github.com/farhan6667/hexswarm/labels/good%20first%20issue) or say hello in
[Discussions](https://github.com/farhan6667/hexswarm/discussions). The [contributing guide](CONTRIBUTING.md) explains the two-minute setup.
It carries the `hacktoberfest` topic, and pull requests are welcome whether or not you take part. Please read [SECURITY.md](SECURITY.md)
before reporting a vulnerability in HexSwarm itself rather than opening a public issue.

If your company can help with test infrastructure, hosting, tools, or funding, the
[sponsor page](https://github.com/farhan6667/farhan6667/blob/main/SPONSOR.md) explains how.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for the attribution and trademark note.

---

<div align="center">

<a href="https://nexaforge.eu.cc/">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/brand/nexaforge-lockup-dark.webp">
    <img src="docs/img/brand/nexaforge-lockup-light.webp" height="48" alt="NexaForge">
  </picture>
</a>
&nbsp;&nbsp;
<a href="https://farhan6667.github.io/portfolio/"><img src="docs/img/brand/sfa-logo.webp" height="64" alt="SFA logo"></a>

**Built by [Syed Farhan Ahmed](https://github.com/farhan6667) (SFA)** at **[NexaForge](https://nexaforge.eu.cc/)**<br>
Cyber security · Vibe coding · Web development and IT infrastructure

[Website](https://nexaforge.eu.cc/) ·
[LinkedIn](https://www.linkedin.com/in/sfa6667) ·
[Portfolio](https://farhan6667.github.io/portfolio/) ·
[Email](mailto:nexaforge.services@gmail.com)

</div>
