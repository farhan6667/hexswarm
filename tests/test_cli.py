from typer.testing import CliRunner

from hexswarm.cli.main import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "hexswarm" in result.stdout


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
