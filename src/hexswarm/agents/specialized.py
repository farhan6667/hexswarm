"""Factory functions that build the standard HexSwarm phase agents.

Each phase agent gets only the tools whose risk level matches its phase, so
even if the LLM tries to call something outside its lane, the tool simply
isn't in its schema list. Combined with ScopeGuard.max_risk_level, this gives
two independent layers stopping a phase from overreaching.
"""
from __future__ import annotations

from hexswarm.agents.base import Agent, AgentConfig, ConfirmFn
from hexswarm.llm.router import LLMRouter
from hexswarm.memory.knowledge import KnowledgeBase
from hexswarm.safety.guard import ToolRiskLevel
from hexswarm.tools.base import ToolRegistry

RECON_PROMPT = """You are the Recon agent in HexSwarm, a multi-agent security testing swarm.
Your job: passively and actively map the target's attack surface -- hosts, open ports,
running services, web technologies. You do not exploit anything. Be methodical: start
passive (whois, DNS), then move to active recon (port scan, fingerprinting) only on
targets that are confirmed in scope. Summarize what you found clearly for the next
agent in the pipeline."""

SCAN_PROMPT = """You are the Vulnerability Scan agent in HexSwarm. You receive a recon
summary describing hosts and services. Your job: identify concrete, specific
vulnerabilities or misconfigurations in those services using your scanning tools.
Do not guess -- run the appropriate tool for what the recon phase actually found
(e.g. only run web_vuln_scan / directory_brute against confirmed HTTP services).
Summarize concrete findings (with severity if you can estimate it) for the exploit agent."""

EXPLOIT_PROMPT = """You are the Exploit agent in HexSwarm. You receive a vulnerability
scan summary. Your job: for each credible, specific finding, decide whether a safe,
scope-authorized proof-of-concept is warranted, and if so use exploit_search to find a
matching known exploit, or metasploit_module_run for a named, well-understood module.
Never invent a module name you are not confident exists. If nothing in the findings
warrants exploitation, say so plainly instead of forcing an action."""

PRIVESC_PROMPT = """You are the Privilege Escalation agent in HexSwarm. You only act if
the exploit agent reports an actual foothold (a working shell/session) on a target.
If no foothold was established, say so and do nothing -- these tools assume you
already have access to the box. Your job: enumerate local privilege escalation vectors
and summarize them for the final report."""

REPORT_PROMPT = """You are the Report agent in HexSwarm. You have no tools. You receive
the full findings log from every phase. Write a clear, professional security assessment
summary in Markdown: an executive summary, a findings table (phase / target / severity /
summary), and a prioritized list of recommendations. Be honest about what was and was not
tested, and never claim a finding is confirmed if the underlying tool call was simulated."""

CTF_PROMPT = """You are the CTF agent in HexSwarm. You receive a path to a local challenge
file (or a raw string, e.g. a captured hash or ciphertext) and a goal describing what kind
of challenge it is, if known. Your job: figure out the flag or the next useful fact about
the file. Work methodically: identify the file type first (file_identify), pull printable
strings (string_extract), check for hidden embedded data (binwalk_scan) on binaries/images,
and try decode_text on any suspicious encoded-looking string you find along the way,
including in the output of your own previous tool calls. Use hash_identify if you find a
hash. Chain tools: the output of one call is often the input to the next (decode a string,
then decode the result again). State the flag clearly the moment you find one, in the exact
format given if the goal specifies one (e.g. flag{...}). If you genuinely cannot find it
after exhausting the obvious angles, say so and summarize what you tried and what you'd
check next with more time."""


def build_phase_agents(
    router: LLMRouter,
    knowledge_base: KnowledgeBase | None = None,
    human_in_the_loop: bool = False,
    confirm_fn: ConfirmFn | None = None,
    models: dict[str, str] | None = None,
) -> dict[str, Agent]:
    """Builds the five standard agents, wired to the live ToolRegistry.

    `models` lets you assign a cheaper/faster model to recon and a stronger
    model to exploit reasoning, e.g.:
        {"recon": "ollama/llama3.1", "exploit": "anthropic/claude-sonnet-5"}
    """
    models = models or {}
    kb = knowledge_base or KnowledgeBase()

    def make(phase: str, prompt: str, risk_levels: list[ToolRiskLevel]) -> Agent:
        tools = list(ToolRegistry.for_phase(risk_levels).values())
        config = AgentConfig(
            name=f"{phase}_agent",
            phase=phase,
            system_prompt=prompt,
            tools=tools,
            model=models.get(phase),
        )
        return Agent(
            config=config,
            router=router,
            knowledge_base=kb,
            human_in_the_loop=human_in_the_loop,
            confirm_fn=confirm_fn,
        )

    return {
        "recon": make("recon", RECON_PROMPT, [ToolRiskLevel.READ_ONLY, ToolRiskLevel.ACTIVE_RECON]),
        "scan": make("scan", SCAN_PROMPT, [ToolRiskLevel.INTRUSIVE]),
        "exploit": make("exploit", EXPLOIT_PROMPT, [ToolRiskLevel.READ_ONLY, ToolRiskLevel.EXPLOIT]),
        "privesc": make("privesc", PRIVESC_PROMPT, [ToolRiskLevel.POST_EXPLOIT]),
        "report": Agent(
            config=AgentConfig(
                name="report_agent",
                phase="report",
                system_prompt=REPORT_PROMPT,
                tools=[],
                model=models.get("report"),
            ),
            router=router,
            knowledge_base=kb,
        ),
    }


def build_ctf_agent(
    router: LLMRouter,
    model: str | None = None,
    max_steps: int = 10,
) -> Agent:
    """Builds the standalone CTF-solving agent (category='ctf' tools only).

    This is intentionally separate from build_phase_agents(): CTF tools
    operate on local files/strings, not network targets, so they don't
    belong in the recon -> scan -> exploit -> privesc pipeline at all.
    """
    tools = list(ToolRegistry.for_category("ctf").values())
    config = AgentConfig(
        name="ctf_agent",
        phase="ctf",
        system_prompt=CTF_PROMPT,
        tools=tools,
        model=model,
        max_steps=max_steps,
    )
    return Agent(config=config, router=router)


AI_SECURITY_PROMPT = """You are the AI Security agent in HexSwarm. Your job: probe a target
LLM/chat application's HTTP endpoint for prompt-injection and system-prompt-leak
weaknesses using prompt_injection_probe. A flagged response is a heuristic hit, not a
confirmed finding: read the actual response text in the tool output and judge for yourself
whether it really complied with the injected instruction before reporting it as a concern.
Summarize which probes were flagged, quote the relevant part of each flagged response, and
note that this is triage, not a substitute for manual review."""


def build_ai_security_agent(
    router: LLMRouter,
    model: str | None = None,
    max_steps: int = 4,
) -> Agent:
    """Builds the standalone AI/LLM application security agent (category='ai-security').

    Separate from the network pentest pipeline for the same reason the CTF agent is:
    its one tool targets an application's chat endpoint specifically, not a general host.
    """
    tools = list(ToolRegistry.for_category("ai-security").values())
    config = AgentConfig(
        name="ai_security_agent",
        phase="ai-security",
        system_prompt=AI_SECURITY_PROMPT,
        tools=tools,
        model=model,
        max_steps=max_steps,
    )
    return Agent(config=config, router=router)
