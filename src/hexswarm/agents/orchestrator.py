"""Swarm coordinator: runs the phase pipeline end to end for one engagement."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from hexswarm.agents.base import Agent, ConfirmFn
from hexswarm.agents.specialized import build_phase_agents, build_verify_agent
from hexswarm.llm.router import LLMRouter
from hexswarm.memory.findings import FindingsStore
from hexswarm.memory.knowledge import KnowledgeBase
from hexswarm.observability import BudgetExceeded
from hexswarm.safety.guard import ScopeGuard, ScopeViolation

DEFAULT_PHASE_ORDER = ["recon", "scan", "exploit", "privesc"]

# Called as progress_callback(event, phase) where event is "start" or "done".
# Lets a CLI show live "Recon agent is working..." feedback instead of going
# silent for however long a phase's tool-call loop takes.
ProgressCallback = Callable[[str, str], None]


@dataclass
class EngagementResult:
    engagement_name: str
    goal: str
    target: str
    phase_summaries: dict[str, str] = field(default_factory=dict)
    report_markdown: str = ""
    findings: FindingsStore | None = None
    budget_exceeded: bool = False


class Orchestrator:
    """Runs recon -> scan -> exploit -> privesc -> report for a single target.

    This is a deliberately simple, linear pipeline rather than a fully
    dynamic handoff graph: predictable ordering makes behavior auditable,
    which matters more for a security tool than clever routing does. Each
    phase still gets the accumulated findings and can decide to do nothing.
    """

    def __init__(
        self,
        router: LLMRouter,
        scope_guard: ScopeGuard,
        findings: FindingsStore | None = None,
        knowledge_base: KnowledgeBase | None = None,
        human_in_the_loop: bool = False,
        confirm_fn: ConfirmFn | None = None,
        models: dict[str, str] | None = None,
        phase_order: list[str] | None = None,
        progress_callback: ProgressCallback | None = None,
        verify: bool = False,
    ) -> None:
        self.router = router
        self.scope_guard = scope_guard
        self.findings = findings or FindingsStore(engagement_name=scope_guard.engagement_name)
        self.phase_order = phase_order or list(DEFAULT_PHASE_ORDER)
        self.progress_callback = progress_callback
        self.verify = verify
        self.agents: dict[str, Agent] = build_phase_agents(
            router=router,
            knowledge_base=knowledge_base,
            human_in_the_loop=human_in_the_loop,
            confirm_fn=confirm_fn,
            models=models,
        )
        if verify:
            self.agents["verify"] = build_verify_agent(router=router, model=(models or {}).get("verify"))

    def _notify(self, event: str, phase: str) -> None:
        if self.progress_callback is not None:
            self.progress_callback(event, phase)

    def run(self, goal: str, target: str) -> EngagementResult:
        result = EngagementResult(
            engagement_name=self.scope_guard.engagement_name,
            goal=goal,
            target=target,
            findings=self.findings,
        )

        try:
            self.scope_guard.check_target(target)
        except ScopeViolation as exc:
            result.phase_summaries["error"] = str(exc)
            result.report_markdown = f"# Engagement aborted\n\n{exc}\n"
            return result

        for phase in self.phase_order:
            agent = self.agents[phase]
            self._notify("start", phase)
            try:
                summary = agent.run(goal=goal, target=target, guard=self.scope_guard, findings=self.findings)
            except ScopeViolation as exc:
                summary = f"Phase halted by scope guard: {exc}"
            except BudgetExceeded as exc:
                # The engagement's cost/token ceiling was crossed mid-phase. Stop the
                # whole pipeline cleanly: record what happened, still write a report over
                # whatever was found before the ceiling, and don't start further phases.
                result.phase_summaries[phase] = f"Phase stopped: {exc}"
                self._notify("done", phase)
                result.budget_exceeded = True
                # The report agent shares this budget, so asking it to write a narrative
                # would just re-trip the ceiling. Emit a plain findings-based report instead.
                result.report_markdown = self._budget_stopped_report(target, exc)
                return result
            result.phase_summaries[phase] = summary
            self._notify("done", phase)

        if self.verify:
            self._notify("start", "verify")
            try:
                verdict = self.agents["verify"].run(
                    goal=goal, target=target, guard=self.scope_guard, findings=self.findings
                )
            except BudgetExceeded as exc:
                verdict = f"Verification skipped: {exc}"
                result.budget_exceeded = True
            result.phase_summaries["verify"] = verdict
            self._notify("done", "verify")

        self._notify("start", "report")
        result.report_markdown = self._generate_report(goal, target)
        self._notify("done", "report")
        return result

    def _generate_report(self, goal: str, target: str) -> str:
        report_agent = self.agents["report"]
        return report_agent.run(goal=goal, target=target, guard=self.scope_guard, findings=self.findings)

    def _budget_stopped_report(self, target: str, exc: Exception) -> str:
        """A plain, LLM-free report written when the budget stopped the run mid-engagement."""
        lines = [
            f"# Engagement stopped: budget exceeded ({target})",
            "",
            f"The run was halted because: {exc}",
            "",
            "Findings collected before the stop:",
            "",
            self.findings.summary_text(),
        ]
        return "\n".join(lines) + "\n"
