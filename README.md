<h1 align="center">HexSwarm</h1>

<p align="center">
  <b>HexSwarm is an open-source Python framework for running AI agents against authorized penetration testing, bug bounty, and CTF targets.</b><br>
  It connects to OpenAI, Anthropic, local Ollama models, or 100+ other providers through one interface, and gives those agents a scoped,
  safety-gated library of real offensive-security tools (recon, vulnerability scanning, exploitation, and privilege escalation), so a single
  high-level goal like "find a web server on this target and check for common vulnerabilities" turns into a coordinated, auditable swarm run.
</p>

<p align="center">
  <a href="https://github.com/farhan6667/hexswarm/actions"><img alt="CI" src="https://github.com/farhan6667/hexswarm/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <a href="https://www.python.org/"><img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue"></a>
</p>

---

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

## Install

```bash
git clone https://github.com/farhan6667/hexswarm.git
cd hexswarm
pip install -e .
```

HexSwarm itself has no heavy dependencies, it's a thin orchestration layer. The underlying security tools (`nmap`, `nuclei`, `gobuster`,
`sqlmap`, `hydra`, `searchsploit`, Metasploit) are expected to live on a proper pentest host (Kali, a security-focused Linux box, or WSL). If a
binary isn't present, the matching tool runs in simulate mode automatically, so the framework and its test suite work anywhere Python runs.

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

It's picked up automatically by whichever phase agent matches its `risk_level`, no orchestrator changes needed.

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

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Please read [SECURITY.md](SECURITY.md) before reporting a
vulnerability in HexSwarm itself.

## License

MIT, see [LICENSE](LICENSE).
