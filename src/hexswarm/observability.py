"""Cost/token budget governance and an engagement trace.

This is HexSwarm's answer to the one problem the 2026 agentic-pentest field
keeps hitting and mostly ignores: agents burn 5-30x the tokens of a chatbot
per task (Gartner 2026), and an autonomous run left unsupervised can quietly
spend real money. Every other framework in this space leads with capability;
almost none let you cap the spend and see where it went.

Two pieces:

- `Budget`: a hard ceiling on total cost (USD) and/or tokens for one
  engagement. The LLM router checks it after every call and raises
  `BudgetExceeded` the moment a ceiling is crossed, which aborts the run
  cleanly instead of silently running up a bill.

- `Telemetry`: an append-only trace of every LLM call and every tool call,
  with tokens, cost, timing, and whether a tool was simulated. It writes one
  JSON object per line (JSONL), so a run is auditable after the fact: what
  the agent actually did, in what order, and what it cost. This is the
  "reasoning-chain / cost trail" that agent-observability guidance in 2026
  recommends, applied to a security tool where the audit trail matters more
  than usual.

Both are optional and default to off: a run with no budget and no telemetry
behaves exactly as before.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


class BudgetExceeded(Exception):
    """Raised when an engagement's cost or token ceiling is crossed."""


@dataclass
class Budget:
    """A hard ceiling for one engagement. A limit of None means 'no limit for this dimension'."""

    max_cost_usd: float | None = None
    max_tokens: int | None = None
    spent_cost_usd: float = 0.0
    spent_tokens: int = 0

    def add(self, cost_usd: float, tokens: int) -> None:
        self.spent_cost_usd += cost_usd
        self.spent_tokens += tokens

    def check(self) -> None:
        """Raise BudgetExceeded if either ceiling has been crossed."""
        if self.max_cost_usd is not None and self.spent_cost_usd > self.max_cost_usd:
            raise BudgetExceeded(
                f"Cost budget exceeded: spent ${self.spent_cost_usd:.4f} of "
                f"${self.max_cost_usd:.4f} limit."
            )
        if self.max_tokens is not None and self.spent_tokens > self.max_tokens:
            raise BudgetExceeded(
                f"Token budget exceeded: used {self.spent_tokens} of {self.max_tokens} limit."
            )

    @property
    def is_unbounded(self) -> bool:
        return self.max_cost_usd is None and self.max_tokens is None


@dataclass
class TraceEvent:
    kind: str  # "llm_call" | "tool_call"
    timestamp: float
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Telemetry:
    """Append-only engagement trace, optionally mirrored to a JSONL file."""

    engagement_name: str = "engagement"
    trace_path: Path | None = None
    events: list[TraceEvent] = field(default_factory=list)
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    llm_calls: int = 0
    tool_calls: int = 0

    def record_llm_call(
        self,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
        phase: str = "",
    ) -> None:
        self.llm_calls += 1
        self.total_cost_usd += cost_usd
        self.total_tokens += prompt_tokens + completion_tokens
        self._append(
            "llm_call",
            {
                "model": model,
                "phase": phase,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cost_usd": round(cost_usd, 6),
            },
        )

    def record_tool_call(
        self,
        tool_name: str,
        target: str,
        simulated: bool,
        success: bool,
        phase: str = "",
        duration_s: float | None = None,
    ) -> None:
        self.tool_calls += 1
        self._append(
            "tool_call",
            {
                "tool_name": tool_name,
                "target": target,
                "simulated": simulated,
                "success": success,
                "phase": phase,
                "duration_s": round(duration_s, 3) if duration_s is not None else None,
            },
        )

    def _append(self, kind: str, detail: dict[str, Any]) -> None:
        event = TraceEvent(kind=kind, timestamp=time.time(), detail=detail)
        self.events.append(event)
        if self.trace_path is not None:
            try:
                self.trace_path.parent.mkdir(parents=True, exist_ok=True)
                with self.trace_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(asdict(event)) + "\n")
            except OSError:
                # A trace-file write failure must never take down the engagement itself.
                pass

    def summary(self) -> str:
        return (
            f"{self.llm_calls} LLM calls, {self.tool_calls} tool calls, "
            f"{self.total_tokens} tokens, ${self.total_cost_usd:.4f}"
        )


def estimate_cost(raw_response: Any) -> tuple[int, int, float]:
    """Extracts (prompt_tokens, completion_tokens, cost_usd) from a LiteLLM response.

    Returns zeros when usage isn't available (e.g. a local Ollama model that reports
    no usage, or a test double), so cost tracking degrades gracefully to "free/unknown"
    rather than crashing the call it's measuring.
    """
    usage = getattr(raw_response, "usage", None)
    prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0) if usage else 0
    completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0) if usage else 0

    cost_usd = 0.0
    try:
        import litellm

        computed = litellm.completion_cost(completion_response=raw_response)
        if computed:
            cost_usd = float(computed)
    except Exception:  # noqa: BLE001 - cost lookup is best-effort, never fatal
        cost_usd = 0.0

    return prompt_tokens, completion_tokens, cost_usd
