from types import SimpleNamespace

import pytest

from hexswarm.agents.base import Agent, AgentConfig
from hexswarm.bench import (
    DEFAULT_MANIFEST,
    BenchmarkChallenge,
    BenchmarkReport,
    load_challenges,
    run_benchmark,
)
from hexswarm.llm.router import LLMRouter
from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel


def fake_response(content):
    message = SimpleNamespace(content=content, tool_calls=[])
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def make_guard():
    return ScopeGuard(engagement_name="bench", allow=["local-file-analysis"], max_risk_level=ToolRiskLevel.READ_ONLY)


def test_load_challenges_reads_the_real_manifest():
    challenges = load_challenges(DEFAULT_MANIFEST)
    assert len(challenges) == 6
    ids = {c.id for c in challenges}
    assert "base64-simple" in ids
    assert "double-base64" in ids
    for c in challenges:
        assert c.file.exists(), f"{c.id}'s challenge file is missing: {c.file}"


def test_load_challenges_missing_manifest_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_challenges(tmp_path / "nope.yaml")


def test_run_benchmark_marks_correct_answer_as_solved():
    challenges = [
        BenchmarkChallenge(id="c1", file=__import__("pathlib").Path("x.txt"), goal="g", flag="flag{ok}")
    ]

    def fn(**kwargs):
        return fake_response("Found it: flag{ok}")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)

    def agent_factory():
        return Agent(config=AgentConfig(name="a", phase="ctf", system_prompt="x", tools=[]), router=router)

    report = run_benchmark(challenges, agent_factory, make_guard)
    assert report.solved_count == 1
    assert report.total_count == 1
    assert report.results[0].solved is True


def test_run_benchmark_marks_wrong_answer_as_unsolved():
    challenges = [
        BenchmarkChallenge(id="c1", file=__import__("pathlib").Path("x.txt"), goal="g", flag="flag{ok}")
    ]

    def fn(**kwargs):
        return fake_response("I couldn't find a flag.")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)

    def agent_factory():
        return Agent(config=AgentConfig(name="a", phase="ctf", system_prompt="x", tools=[]), router=router)

    report = run_benchmark(challenges, agent_factory, make_guard)
    assert report.solved_count == 0
    assert report.results[0].solved is False


def test_run_benchmark_uses_a_fresh_agent_per_challenge():
    challenges = [
        BenchmarkChallenge(id="c1", file=__import__("pathlib").Path("x.txt"), goal="g1", flag="flag{one}"),
        BenchmarkChallenge(id="c2", file=__import__("pathlib").Path("y.txt"), goal="g2", flag="flag{two}"),
    ]
    goals_seen = []
    call_count = {"n": 0}

    def fn(**kwargs):
        call_count["n"] += 1
        messages = kwargs["messages"]
        user_msg = next(m["content"] for m in messages if m["role"] == "user")
        goals_seen.append(user_msg)
        return fake_response("flag{one}" if call_count["n"] == 1 else "flag{two}")

    router = LLMRouter(primary_model="fake/model", completion_fn=fn)

    def agent_factory():
        return Agent(config=AgentConfig(name="a", phase="ctf", system_prompt="x", tools=[]), router=router)

    report = run_benchmark(challenges, agent_factory, make_guard)
    assert report.solved_count == 2
    assert "g1" in goals_seen[0]
    assert "g2" in goals_seen[1]


def test_benchmark_report_markdown_includes_pass_fail():
    report = BenchmarkReport()
    from hexswarm.bench import BenchmarkResult

    report.results = [
        BenchmarkResult(challenge_id="a", solved=True, summary="s"),
        BenchmarkResult(challenge_id="b", solved=False, summary="s"),
    ]
    md = report.to_markdown()
    assert "1/2 solved" in md
    assert "PASS" in md
    assert "FAIL" in md
