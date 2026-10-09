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
