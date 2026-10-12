from typer.testing import CliRunner

import hexswarm.cli.main as cli_main
from hexswarm.cli.main import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "hexswarm" in result.stdout.lower()


def test_version_shows_the_brand():
    result = runner.invoke(app, ["version"])
    assert "NexaForge" in result.stdout
    assert "Syed Farhan Ahmed" in result.stdout


def test_tools_command_lists_registry():
    result = runner.invoke(app, ["tools"])
    assert result.exit_code == 0
    assert "port_scan" in result.stdout
    assert "whois_lookup" in result.stdout


def test_scope_check_authorized(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "engagement_name: demo\nallow:\n  - 'example.com'\nmax_risk_level: intrusive\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scope-check", str(scope), "example.com"])
    assert result.exit_code == 0
    assert "AUTHORIZED" in result.stdout


def test_scope_check_rejected(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "engagement_name: demo\nallow:\n  - 'example.com'\nmax_risk_level: intrusive\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scope-check", str(scope), "notallowed.com"])
    assert result.exit_code == 1
    assert "REJECTED" in result.stdout


def test_scope_check_missing_file(tmp_path):
    result = runner.invoke(app, ["scope-check", str(tmp_path / "nope.yaml"), "example.com"])
    assert result.exit_code == 1
    assert "REJECTED" in result.stdout


def test_ctf_command_missing_file(tmp_path):
    result = runner.invoke(app, ["ctf", "--goal", "find the flag", "--file", str(tmp_path / "nope.bin")])
    assert result.exit_code == 1
    assert "File not found" in result.stdout


def test_run_rejects_out_of_scope_target_before_prompting(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "engagement_name: demo\nallow:\n  - 'example.com'\nmax_risk_level: intrusive\n",
        encoding="utf-8",
    )
    # Never asked to confirm: the scope check runs and fails first, with no LLM call attempted.
    result = runner.invoke(
        app,
        ["run", "--goal", "g", "--target", "notallowed.com", "--scope", str(scope)],
    )
    assert result.exit_code == 1
    assert "Scope error" in result.stdout


def test_run_aborts_when_confirmation_declined(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "engagement_name: demo\nallow:\n  - 'example.com'\nmax_risk_level: intrusive\n",
        encoding="utf-8",
    )
    # Declining the pre-run confirmation must stop before any LLMRouter/litellm call is made.
    result = runner.invoke(
        app,
        ["run", "--goal", "g", "--target", "example.com", "--scope", str(scope)],
        input="n\n",
    )
    assert result.exit_code == 1
    assert "Aborted" in result.stdout


def test_init_wizard_writes_env_and_scope(tmp_path):
    env_out = tmp_path / ".env"
    scope_out = tmp_path / "scope.yaml"
    # Answers in order: model preset "1" (ollama, no API key prompt), engagement name,
    # one allow entry then a blank line to finish, risk-level choice "2", authorized_by.
    answers = "1\nctf-lab\n10.10.10.5\n\n2\ntester\n"

    result = runner.invoke(
        app,
        ["init", "--env-out", str(env_out), "--scope-out", str(scope_out)],
        input=answers,
    )

    assert result.exit_code == 0, result.stdout
    assert env_out.exists()
    assert scope_out.exists()

    env_text = env_out.read_text(encoding="utf-8")
    assert "HEXSWARM_PRIMARY_MODEL=ollama/llama3.1" in env_text

    scope_text = scope_out.read_text(encoding="utf-8")
    assert 'engagement_name: "ctf-lab"' in scope_text
    assert '"10.10.10.5"' in scope_text
    assert 'max_risk_level: "active_recon"' in scope_text
    assert 'authorized_by: "tester"' in scope_text


def test_init_wizard_rejects_empty_scope_and_requires_at_least_one_entry(tmp_path):
    env_out = tmp_path / ".env"
    scope_out = tmp_path / "scope.yaml"
    # Blank line first (rejected), then a real entry, then blank to finish.
    answers = "1\nctf-lab\n\n10.10.10.5\n\n2\ntester\n"

    result = runner.invoke(
        app,
        ["init", "--env-out", str(env_out), "--scope-out", str(scope_out)],
        input=answers,
    )

    assert result.exit_code == 0, result.stdout
    assert "at least one entry is required" in result.stdout.lower()
    assert '"10.10.10.5"' in scope_out.read_text(encoding="utf-8")


def test_init_wizard_writes_api_key_for_cloud_provider(tmp_path):
    env_out = tmp_path / ".env"
    scope_out = tmp_path / "scope.yaml"
    # Model preset "2" is Anthropic, which does prompt for an API key.
    answers = "2\nsk-test-dummy-key\nctf-lab\n10.10.10.5\n\n1\ntester\n"

    result = runner.invoke(
        app,
        ["init", "--env-out", str(env_out), "--scope-out", str(scope_out)],
        input=answers,
    )

    assert result.exit_code == 0, result.stdout
    env_text = env_out.read_text(encoding="utf-8")
    assert "HEXSWARM_PRIMARY_MODEL=anthropic/claude-sonnet-5" in env_text
    assert "ANTHROPIC_API_KEY=sk-test-dummy-key" in env_text


def test_doctor_passes_when_ollama_reachable(monkeypatch):
    monkeypatch.setenv("HEXSWARM_PRIMARY_MODEL", "ollama/llama3.1")
    monkeypatch.setattr(cli_main.urllib.request, "urlopen", lambda *a, **k: object())

    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Ready to run" in result.stdout


def test_doctor_fails_when_ollama_unreachable(monkeypatch):
    monkeypatch.setenv("HEXSWARM_PRIMARY_MODEL", "ollama/llama3.1")

    def raise_unreachable(*a, **k):
        raise cli_main.urllib.error.URLError("connection refused")

    monkeypatch.setattr(cli_main.urllib.request, "urlopen", raise_unreachable)

    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "FAIL" in result.stdout


def test_doctor_checks_cloud_provider_api_key(monkeypatch):
    monkeypatch.setenv("HEXSWARM_PRIMARY_MODEL", "anthropic/claude-sonnet-5")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "ANTHROPIC_API_KEY" in result.stdout

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-dummy-key")
    result_ok = runner.invoke(app, ["doctor"])
    assert result_ok.exit_code == 0
    assert "Ready to run" in result_ok.stdout


def test_mcp_server_command_rejects_missing_scope(tmp_path):
    result = runner.invoke(app, ["mcp-server", "--scope", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 1
    assert "Scope error" in result.stdout


def test_bench_command_runs_end_to_end(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from hexswarm.bench import DEFAULT_MANIFEST, load_challenges
    from hexswarm.llm.router import LLMRouter

    # Script the fake model to answer each challenge, in manifest order, with that
    # challenge's own real flag, proving a genuinely correct model is scored 6/6.

    challenges = load_challenges(DEFAULT_MANIFEST)
    flags_in_order = iter(c.flag for c in challenges)

    def fake_completion_fn_all_correct(**kwargs):
        content = next(flags_in_order, "no idea")
        message = SimpleNamespace(content=content, tool_calls=[])
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    monkeypatch.setattr(LLMRouter, "_get_completion_fn", lambda self: fake_completion_fn_all_correct)

    report_out = tmp_path / "bench_report.md"
    result = runner.invoke(app, ["bench", "--report-out", str(report_out)])

    assert result.exit_code == 0, result.stdout
    assert "6/6 solved" in result.stdout
    assert report_out.exists()
    assert "6/6 solved" in report_out.read_text(encoding="utf-8")


def test_ai_audit_rejects_out_of_scope_target(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "engagement_name: demo\nallow:\n  - 'app.example.com'\nmax_risk_level: intrusive\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app, ["ai-audit", "--target", "https://evil.other.com/api/chat", "--scope", str(scope)]
    )
    assert result.exit_code == 1
    assert "Scope error" in result.stdout


def test_ai_audit_runs_end_to_end(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from hexswarm.llm.router import LLMRouter

    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "engagement_name: demo\nallow:\n  - 'app.example.com'\nmax_risk_level: intrusive\n",
        encoding="utf-8",
    )

    def fake_post(url, json=None, timeout=None):
        class R:
            def json(self_inner):
                return {"response": "I can't help with that."}
        return R()

    monkeypatch.setattr("hexswarm.tools.ai_security.requests.post", fake_post)

    call_count = {"n": 0}

    def fake_completion_fn_sequenced(**kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            tc = SimpleNamespace(
                id="c1",
                function=SimpleNamespace(
                    name="prompt_injection_probe",
                    arguments='{"target": "https://app.example.com/api/chat"}',
                ),
            )
            message = SimpleNamespace(content="", tool_calls=[tc])
        else:
            message = SimpleNamespace(content="No probes were flagged.", tool_calls=[])
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    monkeypatch.setattr(LLMRouter, "_get_completion_fn", lambda self: fake_completion_fn_sequenced)

    result = runner.invoke(
        app, ["ai-audit", "--target", "https://app.example.com/api/chat", "--scope", str(scope)]
    )
    assert result.exit_code == 0, result.stdout
    assert "No probes were flagged" in result.stdout


def test_playbooks_command_lists_builtins():
    result = runner.invoke(app, ["playbooks"])
    assert result.exit_code == 0
    assert "recon-only" in result.stdout
    assert "web-assessment" in result.stdout
    assert "full-engagement" in result.stdout


def test_run_rejects_missing_goal_and_playbook(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "engagement_name: demo\nallow:\n  - 'example.com'\nmax_risk_level: intrusive\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["run", "--target", "example.com", "--scope", str(scope)])
    assert result.exit_code == 1
    assert "provide --goal" in result.stdout


def test_run_playbook_unknown_name(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "engagement_name: demo\nallow:\n  - 'example.com'\nmax_risk_level: intrusive\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app, ["run", "--target", "example.com", "--scope", str(scope), "--playbook", "does-not-exist"]
    )
    assert result.exit_code == 1
    assert "Playbook error" in result.stdout


def test_lab_list_command():
    result = runner.invoke(app, ["lab", "list"])
    assert result.exit_code == 0
    assert "juice-shop" in result.stdout


def test_lab_up_requires_name():
    result = runner.invoke(app, ["lab", "up"])
    assert result.exit_code == 1
    assert "lab name is required" in result.stdout.lower()


def test_lab_unknown_action():
    result = runner.invoke(app, ["lab", "sideways"])
    assert result.exit_code == 1
    assert "Unknown action" in result.stdout


def test_lab_up_without_docker(monkeypatch):
    monkeypatch.setattr("hexswarm.labs.docker_available", lambda: False)
    result = runner.invoke(app, ["lab", "up", "juice-shop"])
    assert result.exit_code == 1
    assert "Docker not found" in result.stdout


def test_run_mcp_config_missing_file(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "engagement_name: demo\nallow:\n  - 'example.com'\nmax_risk_level: intrusive\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["run", "--goal", "g", "--target", "example.com", "--scope", str(scope),
         "--mcp-config", str(tmp_path / "nope.yaml")],
    )
    assert result.exit_code == 1
    assert "MCP config error" in result.stdout


def test_run_mcp_config_registers_remote_tools(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from hexswarm.llm.router import LLMRouter
    from hexswarm.mcp.client import McpServerConfig, RemoteMCPTool
    from hexswarm.tools.base import ToolRegistry

    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "engagement_name: demo\nallow:\n  - 'example.com'\nmax_risk_level: intrusive\n",
        encoding="utf-8",
    )
    mcp_cfg = tmp_path / "mcp.yaml"
    mcp_cfg.write_text("servers:\n  - name: svc\n    command: echo\n", encoding="utf-8")

    fake_tool = RemoteMCPTool(
        server=McpServerConfig(name="svc", command="echo", category="pentest"),
        remote_name="demo_scan",
        description="d",
        input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
    )
    monkeypatch.setattr("hexswarm.mcp.client.load_all_remote_tools", lambda p: [fake_tool])
    monkeypatch.setattr(
        LLMRouter, "_get_completion_fn",
        lambda self: (lambda **k: SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=[]))])),
    )

    result = runner.invoke(
        app,
        ["run", "--goal", "g", "--target", "example.com", "--scope", str(scope),
         "--mcp-config", str(mcp_cfg), "--yes"],
    )
    assert result.exit_code == 0, result.stdout
    assert "Loaded 1 tool(s) from external MCP" in result.stdout
    assert "svc.demo_scan" in ToolRegistry.all()
    # cleanup global registry so the injected tool doesn't leak into other tests
    ToolRegistry.all().pop("svc.demo_scan", None)
    ToolRegistry._tools.pop("svc.demo_scan", None)


def test_compliance_command_maps_findings(tmp_path):
    import json
    findings_json = tmp_path / "findings.json"
    findings_json.write_text(json.dumps({
        "engagement_name": "demo",
        "findings": [
            {"phase": "scan", "tool_name": "sql_injection_scan", "target": "http://x",
             "summary": "SQL injection found", "severity": "high", "raw_output": "", "timestamp": "t"},
        ],
    }), encoding="utf-8")
    out = tmp_path / "mapping.md"
    result = runner.invoke(app, ["compliance", "--findings", str(findings_json), "--out", str(out)])
    assert result.exit_code == 0, result.stdout
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "6.2.4" in text or "Secure coding" in text
    assert "advisory" in text.lower()


def test_compliance_command_missing_file(tmp_path):
    result = runner.invoke(app, ["compliance", "--findings", str(tmp_path / "nope.json")])
    assert result.exit_code == 1
    assert "not found" in result.stdout.lower()


def test_compliance_command_unknown_framework(tmp_path):
    import json
    fj = tmp_path / "f.json"
    fj.write_text(json.dumps({"engagement_name": "d", "findings": [
        {"phase": "scan", "tool_name": "sql_injection_scan", "target": "x", "summary": "sqli",
         "severity": "high", "raw_output": "", "timestamp": "t"}]}), encoding="utf-8")
    result = runner.invoke(app, ["compliance", "--findings", str(fj), "--framework", "hipaa"])
    assert result.exit_code == 1
    assert "Unknown framework" in result.stdout
