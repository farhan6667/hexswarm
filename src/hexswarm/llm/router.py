"""Model-agnostic LLM router built on LiteLLM.

A single interface reaches OpenAI, Anthropic, Ollama (local models), and 100+
other providers LiteLLM supports, using the same "provider/model" string
convention, e.g.:

    "openai/gpt-4o"
    "anthropic/claude-sonnet-5"
    "ollama/llama3.1"
    "ollama/qwen2.5-coder"

Agents never import a provider SDK directly. They call LLMRouter.complete(),
which also provides an ordered fallback list so a failing/unavailable
provider doesn't stall an engagement.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hexswarm.observability import BudgetExceeded


@dataclass
class LLMMessage:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    tool_call_id: str | None = None
    name: str | None = None


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    model_used: str = ""
    raw: Any = None


class LLMRouter:
    """Routes chat completions across a prioritized list of models.

    Parameters
    ----------
    primary_model:
        LiteLLM-style model string used first, e.g. "anthropic/claude-sonnet-5".
    fallback_models:
        Tried in order if the primary raises. Lets a swarm keep running on a
        local Ollama model if a cloud provider is rate-limited or has no key.
    completion_fn:
        Injection point for tests. Defaults to litellm.completion. Signature
        must match `litellm.completion(**kwargs) -> ModelResponse`.
    """

    def __init__(
        self,
        primary_model: str,
        fallback_models: list[str] | None = None,
        completion_fn: Callable[..., Any] | None = None,
        temperature: float = 0.2,
        max_retries: int = 2,
        telemetry: Any = None,
        budget: Any = None,
        phase: str = "",
    ) -> None:
        self.primary_model = primary_model
        self.fallback_models = fallback_models or []
        self.temperature = temperature
        self.max_retries = max_retries
        self._completion_fn = completion_fn
        # Optional cost/observability hooks. Both default to None, in which case
        # the router behaves exactly as before: no tracking, no budget ceiling.
        self.telemetry = telemetry
        self.budget = budget
        self.phase = phase

    def _get_completion_fn(self) -> Callable[..., Any]:
        if self._completion_fn is not None:
            return self._completion_fn
        import litellm  # imported lazily so tests never need the dependency

        return litellm.completion

    def _model_candidates(self) -> list[str]:
        return [self.primary_model, *self.fallback_models]

    def complete(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
    ) -> LLMResponse:
        completion_fn = self._get_completion_fn()
        payload_messages = [
            {
                "role": m.role,
                "content": m.content,
                **({"tool_call_id": m.tool_call_id} if m.tool_call_id else {}),
                **({"name": m.name} if m.name else {}),
            }
            for m in messages
        ]

        candidates = [model] if model else self._model_candidates()
        last_error: Exception | None = None

        for candidate in candidates:
            for attempt in range(self.max_retries):
                try:
                    kwargs: dict[str, Any] = {
                        "model": candidate,
                        "messages": payload_messages,
                        "temperature": self.temperature,
                    }
                    if tools:
                        kwargs["tools"] = tools
                        kwargs["tool_choice"] = "auto"

                    raw = completion_fn(**kwargs)
                    response = self._parse_response(raw, candidate)
                    self._record_cost(raw, candidate)
                    return response
                except BudgetExceeded:
                    # A budget ceiling is a hard stop for the whole engagement, not a
                    # provider failure to retry or fall back from. Propagate it immediately.
                    raise
                except Exception as exc:  # noqa: BLE001 - provider errors vary widely
                    last_error = exc
                    continue
        raise RuntimeError(
            f"All model candidates failed: {candidates}. Last error: {last_error}"
        ) from last_error

    def _record_cost(self, raw: Any, model_used: str) -> None:
        """Records token/cost usage and enforces the budget ceiling, if either is configured.

        Runs after a successful completion. If the budget is now exceeded this raises
        BudgetExceeded, which the caller treats as an engagement-ending condition.
        """
        if self.telemetry is None and self.budget is None:
            return
        from hexswarm.observability import estimate_cost

        prompt_tokens, completion_tokens, cost_usd = estimate_cost(raw)
        if self.telemetry is not None:
            self.telemetry.record_llm_call(
                model=model_used,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_usd=cost_usd,
                phase=self.phase,
            )
        if self.budget is not None:
            self.budget.add(cost_usd, prompt_tokens + completion_tokens)
            self.budget.check()

    @staticmethod
    def _parse_response(raw: Any, model_used: str) -> LLMResponse:
        choice = raw.choices[0]
        message = choice.message
        content = getattr(message, "content", None) or ""

        tool_calls: list[ToolCall] = []
        raw_tool_calls = getattr(message, "tool_calls", None) or []
        for tc in raw_tool_calls:
            import json

            args_raw = tc.function.arguments
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else dict(args_raw)
            except (ValueError, TypeError):
                args = {"_raw": args_raw}
            tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))

        return LLMResponse(content=content, tool_calls=tool_calls, model_used=model_used, raw=raw)
