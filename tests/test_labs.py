import pytest

from hexswarm.labs import available_labs, compose_command, run_lab_action, scope_file_for


def test_juice_shop_lab_is_bundled():
    labs = available_labs()
    assert "juice-shop" in labs
    assert labs["juice-shop"].exists()


def test_juice_shop_has_a_matching_scope_file():
    scope = scope_file_for("juice-shop")
    assert scope is not None
    assert scope.exists()
    assert "localhost" in scope.read_text(encoding="utf-8")


def test_scope_files_are_not_listed_as_labs():
    # a *.scope.yaml must never be treated as a lab compose file
    assert "juice-shop.scope" not in available_labs()


def test_compose_command_up_is_detached():
    from pathlib import Path

    cmd = compose_command(Path("examples/labs/juice-shop.yaml"), "up")
    assert cmd[:2] == ["docker", "compose"]
    assert cmd[-2:] == ["up", "-d"]


def test_compose_command_down():
    from pathlib import Path

    cmd = compose_command(Path("x.yaml"), "down")
    assert cmd[-1] == "down"


def test_compose_command_rejects_unknown_action():
    from pathlib import Path

    with pytest.raises(ValueError):
        compose_command(Path("x.yaml"), "restart")


def test_run_lab_action_unknown_lab_raises():
    with pytest.raises(KeyError):
        run_lab_action("does-not-exist", "up")


def test_run_lab_action_invokes_compose(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        from types import SimpleNamespace

        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("hexswarm.labs.subprocess.run", fake_run)
    run_lab_action("juice-shop", "up")
    assert captured["command"][:2] == ["docker", "compose"]
    assert captured["command"][-2:] == ["up", "-d"]
    assert any("juice-shop" in part for part in captured["command"])
