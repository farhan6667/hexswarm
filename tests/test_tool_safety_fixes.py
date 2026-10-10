"""Regression tests for the audit-pass fixes in base.py/exploit.py/privesc.py.

Each test here corresponds to a real bug found during review, not a
hypothetical: see the comments in the tool source files for the full
explanation of what was wrong and why.
"""
import pytest

from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel
from hexswarm.tools.exploit import ExploitSearch, MetasploitModuleRun
from hexswarm.tools.privesc import LinuxPrivescEnum, WindowsPrivescEnum


def narrow_guard(max_risk=ToolRiskLevel.POST_EXPLOIT):
    """A guard whose allow list deliberately does NOT cover arbitrary strings,
    so any tool that wrongly scope-checks a non-network 'target' value fails."""
    return ScopeGuard(engagement_name="t", allow=["10.10.10.0/24"], max_risk_level=max_risk)


def test_exploit_search_does_not_scope_check_its_query_string(monkeypatch):
    tool = ExploitSearch()
    monkeypatch.setattr(tool, "is_available", lambda: False)
    # "vsftpd 2.3.4" is not a host/IP/CIDR and will never match the allow list above;
    # this must NOT raise ScopeViolation, because it's a local DB query, not a network call.
    result = tool.run(narrow_guard(), target="vsftpd 2.3.4")
    assert result.simulated is True
    assert result.success is True


def test_exploit_search_still_honors_max_risk_level():
    tool = ExploitSearch()
    guard = narrow_guard(max_risk=ToolRiskLevel.ACTIVE_RECON)  # below read_only's own tier? no: read_only < active_recon
    # read_only is allowed up to and including active_recon cap
    tool.run(guard, target="vsftpd 2.3.4")  # should not raise


def test_linux_privesc_enum_builds_ssh_command_without_curl_pipe():
    tool = LinuxPrivescEnum()
    cmd = tool.build_command(target="10.10.10.5", ssh_user="root", remote_script_path="/tmp/linpeas.sh")
    assert cmd[0] == "ssh"
    assert cmd[1] == "root@10.10.10.5"
    assert "curl" not in " ".join(cmd)
    assert "/tmp/linpeas.sh" in cmd[2]


def test_linux_privesc_enum_scope_checks_the_bare_host(monkeypatch):
    tool = LinuxPrivescEnum()
    monkeypatch.setattr(tool, "is_available", lambda: False)
    guard = ScopeGuard(engagement_name="t", allow=["10.10.10.5"], max_risk_level=ToolRiskLevel.POST_EXPLOIT)
    # Must authorize on the host alone, not "user@host" (which would never match the allow list).
    # If this scope-checked "root@10.10.10.5" instead of "10.10.10.5", it would raise ScopeViolation here.
    result = tool.run(guard, target="10.10.10.5", ssh_user="root")
    assert result.simulated is True


def test_windows_privesc_enum_escapes_single_quotes_in_target():
    tool = WindowsPrivescEnum()
    malicious_target = "x' ; Remove-Item -Recurse -Force C:\\ ; '"
    cmd = tool.build_command(target=malicious_target)
    command_text = cmd[-1]
    # The escaped form must not contain an unescaped closing quote followed by the injected text
    assert "''" in command_text  # single quote was doubled, i.e. escaped
    assert "-ComputerName 'x'' ; Remove-Item" in command_text


def test_windows_privesc_enum_binary_matches_actual_argv0():
    tool = WindowsPrivescEnum()
    cmd = tool.build_command(target="WIN-HOST01")
    assert cmd[0] == tool.binary == "pwsh"


def test_metasploit_rejects_newline_smuggled_in_module():
    tool = MetasploitModuleRun()
    with pytest.raises(ValueError):
        tool.build_command(target="10.10.10.5", module="exploit/x\nset PAYLOAD evil")


def test_metasploit_rejects_newline_smuggled_in_target():
    tool = MetasploitModuleRun()
    with pytest.raises(ValueError):
        tool.build_command(target="10.10.10.5\nset PAYLOAD evil", module="exploit/x")


def test_metasploit_builds_clean_resource_script_for_valid_input():
    tool = MetasploitModuleRun()
    cmd = tool.build_command(target="10.10.10.5", module="exploit/unix/ftp/vsftpd_234_backdoor")
    script = cmd[-1]
    assert "use exploit/unix/ftp/vsftpd_234_backdoor" in script
    assert "set RHOSTS 10.10.10.5" in script
