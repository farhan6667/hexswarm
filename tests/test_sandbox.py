from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel
from hexswarm.tools.recon import PortScan
from hexswarm.tools.sandbox import configure_sandbox, current_sandbox, wrap_command


def teardown_function():
    # configure_sandbox mutates module-level state; reset after every test so
    # sandbox mode never leaks into an unrelated test elsewhere in the suite.
    configure_sandbox(mode="host")


def test_host_mode_leaves_command_unchanged():
    configure_sandbox(mode="host")
    command = ["nmap", "-sV", "scanme.nmap.org"]
    assert wrap_command(command) == command


def test_docker_mode_wraps_command():
    configure_sandbox(mode="docker", image="hexswarm-toolchain:latest", network="none")
    command = ["nmap", "-sV", "scanme.nmap.org"]
    wrapped = wrap_command(command)
    assert wrapped[:3] == ["docker", "run", "--rm"]
    assert "--network" in wrapped
    assert "none" in wrapped
    assert wrapped[-3:] == command
    assert "hexswarm-toolchain:latest" in wrapped


def test_docker_mode_uses_configured_image_and_network():
    configure_sandbox(mode="docker", image="custom:tag", network="bridge")
    wrapped = wrap_command(["whoami"])
    assert "custom:tag" in wrapped
    assert "bridge" in wrapped


def test_configure_sandbox_defaults_to_host():
    configure_sandbox(mode="docker")
    configure_sandbox(mode="host")
    assert current_sandbox().mode == "host"
    assert wrap_command(["echo", "hi"]) == ["echo", "hi"]


def test_tool_is_available_in_docker_mode_without_host_binary(monkeypatch):
    # PortScan's binary (nmap) is treated as present in docker mode even if this
    # test host doesn't have it, because it's expected to live in the sandbox image.
    configure_sandbox(mode="docker")
    tool = PortScan()
    assert tool.is_available() is True


def test_tool_run_wraps_command_in_docker_mode(monkeypatch):
    configure_sandbox(mode="docker", image="hexswarm-toolchain:latest")
    tool = PortScan()

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        from types import SimpleNamespace

        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("hexswarm.tools.base.subprocess.run", fake_run)

    guard = ScopeGuard(engagement_name="t", allow=["scanme.nmap.org"], max_risk_level=ToolRiskLevel.POST_EXPLOIT)
    result = tool.run(guard, target="scanme.nmap.org")

    assert result.simulated is False
    assert result.success is True
    assert captured["command"][:3] == ["docker", "run", "--rm"]
    assert "nmap" in captured["command"]
