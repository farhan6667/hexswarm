"""Base Agent: an LLM + a bounded toolset + a scope guard, in a tool-call loop.

Every specialized agent (recon, scan, exploit, privesc) is the same loop with
a different system prompt and a different slice of the tool registry. Each
step:

1. Sends the conversation + its own tool schemas to the LLM.
2. If the LLM requests tool calls, each is optionally confirmed (HITL hook),
   then executed through ScopeGuard, and the result is fed back as a tool
   message.
3. Repeats until the LLM responds with no tool calls (its handoff summary) or
   `max_steps` is reached.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from hexswarm.llm.router import LLMMessage, LLMRouter
from hexswarm.memory.findings import Finding, FindingsStore
from hexswarm.memory.knowledge import KnowledgeBase
from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel
from hexswarm.tools.base import Tool, ToolRegistry

ConfirmFn = Callable[[str, dict], bool]

# A tool result's severity as recorded in the shared FindingsStore. This is a
# provisional, conservative default based on risk tier and outcome, not a
# CVSS score: a successful exploit or post-exploit run is flagged high enough
# that it can't get lost in a findings list sorted or filtered by severity,
# and the report agent still writes the real narrative on top of it. A
# failed or simulated run never outranks a genuine success at the same tier.
_SEVERITY_BY_RISK_ON_SUCCESS: dict[ToolRiskLevel, str] = {
    ToolRiskLevel.READ_ONLY: "info",
    ToolRiskLevel.ACTIVE_RECON: "info",
    ToolRiskLevel.INTRUSIVE: "low",
    ToolRiskLevel.EXPLOIT: "high",
    ToolRiskLevel.POST_EXPLOIT: "critical",
}


def _infer_severity(tool: Tool, success: bool, simulated: bool) -> str:
    if simulated or not success:
        return "info"
    return _SEVERITY_BY_RISK_ON_SUCCESS.get(tool.risk_level, "info")


@dataclass
class AgentConfig:
    name: str
    phase: str  # "recon" | "scan" | "exploit" | "privesc" | "report"
    system_prompt: str
    tools: list[Tool] = field(default_factory=list)
    model: str | None = None  # overrides the router's primary model for this agent
    max_steps: int = 6


class Agent:
    def __init__(
        self,
        config: AgentConfig,
        router: LLMRouter,
        knowledge_base: KnowledgeBase | None = None,
        human_in_the_loop: bool = False,
        confirm_fn: ConfirmFn | None = None,
    ) -> None:
        self.config = config
        self.router = router
        self.knowledge_base = knowledge_base or KnowledgeBase()
        self.human_in_the_loop = human_in_the_loop
        self.confirm_fn = confirm_fn
        self._tools_by_name = {t.name: t for t in config.tools}

    def _confirm(self, tool_name: str, args: dict) -> bool:
        if not self.human_in_the_loop:
            return True
        if self.confirm_fn is None:
            # HITL requested but no confirm_fn wired up: fail safe, skip the call.
            return False
        return self.confirm_fn(tool_name, args)

    def run(
        self,
        goal: str,
        target: str,
        guard: ScopeGuard,
        findings: FindingsStore,
    ) -> str:
        """Runs the tool-call loop for this agent and returns its handoff summary."""
        knowledge_hints = self._gather_hints(target, findings)

        messages = [
            LLMMessage(role="system", content=self.config.system_prompt),
            LLMMessage(
                role="user",
                content=(
                    f"Engagement goal: {goal}\n"
                    f"Current target: {target}\n"
                    f"Findings so far:\n{findings.summary_text()}\n"
                    f"Relevant knowledge-base hints:\n{knowledge_hints}\n\n"
                    f"Use your available tools to make progress on this phase ({self.config.phase}). "
                    "When you have nothing more useful to do in this phase, respond with a short "
                    "plain-text handoff summary and no further tool calls."
                ),
            ),
        ]

        tool_schemas = ToolRegistry.schemas_for(self.config.tools) if self.config.tools else None

        for _ in range(self.config.max_steps):
            response = self.router.complete(messages, tools=tool_schemas, model=self.config.model)

            if not response.tool_calls:
                return response.content or "(agent produced no summary)"

            messages.append(LLMMessage(role="assistant", content=response.content or ""))

            for call in response.tool_calls:
                result_text = self._execute_tool(call.name, call.arguments, guard, findings)
                messages.append(
                    LLMMessage(
                        role="tool",
                        content=result_text,
                        tool_call_id=call.id,
                        name=call.name,
                    )
                )

        return "(reached max_steps without a final handoff summary)"

    def _gather_hints(self, target: str, findings: FindingsStore) -> str:
        banners = " ".join(f.summary for f in findings.all()) + " " + target
        hints = self.knowledge_base.lookup(banners)
        if not hints:
            return "(none matched)"
        lines = []
        for hint in hints:
            lines.append(f"- {hint.service}: " + "; ".join(hint.checklist))
        return "\n".join(lines)

    def _execute_tool(
        self,
        tool_name: str,
        args: dict,
        guard: ScopeGuard,
        findings: FindingsStore,
    ) -> str:
        tool = self._tools_by_name.get(tool_name)
        if tool is None:
            return f"Error: tool '{tool_name}' is not available to the {self.config.name} agent."

        if not self._confirm(tool_name, args):
            return f"Tool call '{tool_name}' was not confirmed by the operator and was skipped."

        try:
            result = tool.run(guard, **args)
        except ScopeViolation as exc:
            return f"Scope violation, tool not executed: {exc}"
        except Exception as exc:  # noqa: BLE001 - surface any adapter failure to the agent
            return f"Tool '{tool_name}' raised an error: {exc}"

        findings.add(
            Finding(
                phase=self.config.phase,
                tool_name=tool.name,
                target=result.target,
                summary=result.output[:500],
                severity=_infer_severity(tool, result.success, result.simulated),
                raw_output=result.output,
                command=result.command,
                simulated=result.simulated,
            )
        )
        prefix = "[SIMULATED] " if result.simulated else ""
        status = "succeeded" if result.success else "failed"
        return f"{prefix}Tool '{tool_name}' {status}.\nOutput:\n{result.output}\nError:\n{result.error}"
