"""Regression tests for the second external-review pass (Allen Clark, 2026-10-23).

Each test corresponds to one of the reviewer's points. See SECURITY.md's "Known limits"
section for the points that were checked and did NOT reproduce, or that are stated as an
honest, un-fixed limitation rather than silently claimed closed.
"""
import json

import pytest

from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel
from hexswarm.safety.paths import PathConfinementError, confine_path
from hexswarm.tools.ai_security import LlmScan, PromptInjectionProbe
from hexswarm.tools.base import ToolRegistry, reject_leading_dash
from hexswarm.tools.ctf import FileIdentify
from hexswarm.tools.privesc import LinuxPrivescEnum
from hexswarm.tools.recon import SubdomainTakeover
from hexswarm.tools.scan import DirectoryBrute, PasswordBruteForce


def guard(allow=None, max_risk=ToolRiskLevel.POST_EXPLOIT):
    return ScopeGuard(engagement_name="t", allow=allow or ["10.10.10.0/24", "*.lab.local"], max_risk_level=max_risk)


# --- Point 4: leading-dash / option injection -------------------------------------------

def test_reject_leading_dash_rejects_a_flag_looking_value():
    with pytest.raises(ValueError):
        reject_leading_dash("--script=evil", "target")


def test_reject_leading_dash_allows_an_ordinary_value():
    reject_leading_dash("10.10.10.5", "target")  # should not raise


def test_tool_run_rejects_a_dash_leading_target(monkeypatch):
    tool = ToolRegistry.get("port_scan")
    monkeypatch.setattr(tool, "is_available", lambda: False)
    with pytest.raises(ValueError):
        tool.run(guard(), target="--script=vuln")


def test_linux_privesc_enum_rejects_a_dash_leading_ssh_user(monkeypatch):
    tool = LinuxPrivescEnum()
    monkeypatch.setattr(tool, "is_available", lambda: False)
    with pytest.raises(ValueError):
        tool.run(guard(), target="10.10.10.5", ssh_user="-oProxyCommand=evil")


# --- Point 2: file-content targets that bypass the host scope check ---------------------

def test_subdomain_takeover_rejects_an_out_of_scope_subdomain_in_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    subs = tmp_path / "subs.txt"
    subs.write_text("in-scope.lab.local\nevil.other.com\n")
    tool = SubdomainTakeover()
    with pytest.raises(ScopeViolation):
        tool.run(guard(), target=str(subs))


def test_subdomain_takeover_allows_a_file_of_only_in_scope_subdomains(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    subs = tmp_path / "subs.txt"
    subs.write_text("one.lab.local\ntwo.lab.local\n")
    tool = SubdomainTakeover()
    tool.is_available = lambda: False  # force simulate mode, no real SubOver invocation needed
    result = tool.run(guard(), target=str(subs))
    assert result.simulated is True


def test_llm_scan_rejects_a_rest_config_pointing_outside_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    cfg = tmp_path / "rest.json"
    cfg.write_text(json.dumps({"rest": {"uri": "https://evil.other.com/v1/chat"}}))
    tool = LlmScan()
    with pytest.raises(ScopeViolation):
        tool.run(guard(), target="my-model", config=str(cfg))


def test_llm_scan_allows_a_rest_config_pointing_inside_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    cfg = tmp_path / "rest.json"
    cfg.write_text(json.dumps({"rest": {"uri": "https://api.lab.local/v1/chat"}}))
    tool = LlmScan()
    tool.is_available = lambda: False
    result = tool.run(guard(), target="my-model", config=str(cfg))
    assert result.simulated is True


# --- Point 5: arbitrary local file reads via wordlist/userlist/passlist/CTF tools --------

def test_confine_path_rejects_a_path_outside_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    with pytest.raises(PathConfinementError):
        confine_path("/etc/passwd" if not tmp_path.drive else "C:/Windows/win.ini", "target")


def test_confine_path_allows_a_path_inside_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    (tmp_path / "wordlist.txt").write_text("admin\n")
    confine_path("wordlist.txt", "wordlist")  # should not raise


def test_file_identify_rejects_a_path_outside_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    tool = FileIdentify()
    outside = tmp_path.parent / "outside.bin"
    outside.write_bytes(b"x")
    with pytest.raises(PathConfinementError):
        tool.build_command(target=str(outside))


def test_directory_brute_rejects_a_wordlist_outside_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    tool = DirectoryBrute()
    outside = tmp_path.parent / "secrets.txt"
    outside.write_text("admin\n")
    with pytest.raises(PathConfinementError):
        tool.build_command(target="https://example.com", wordlist=str(outside))


def test_directory_brute_default_wordlist_is_not_path_confined():
    # The built-in default is a fixed system path, not operator/agent input.
    tool = DirectoryBrute()
    cmd = tool.build_command(target="https://example.com")
    assert "/usr/share/wordlists/dirb/common.txt" in cmd


def test_password_brute_force_rejects_an_out_of_working_dir_userlist(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    tool = PasswordBruteForce()
    outside = tmp_path.parent / "users.txt"
    outside.write_text("admin\n")
    with pytest.raises(PathConfinementError):
        tool.build_command(target="10.10.10.5", service="ssh", userlist=str(outside), passlist="passlist.txt")


# --- Point 3: prompt_injection_probe following a redirect out of scope ------------------

def test_prompt_injection_probe_disables_redirects(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None, allow_redirects=None):
        captured["allow_redirects"] = allow_redirects
        from types import SimpleNamespace
        return SimpleNamespace(json=lambda: {"response": "ok"}, text="ok")

    monkeypatch.setattr("hexswarm.tools.ai_security.requests.post", fake_post)
    tool = PromptInjectionProbe()
    tool.run(guard(allow=["app.lab.local"]), target="https://app.lab.local/chat")
    assert captured["allow_redirects"] is False


# --- Point 1: IP wildcard claimed to match 0.0.0.0/0 (checked, did not reproduce) --------

def test_octet_wildcard_allow_rule_does_not_admit_an_unrelated_host():
    g = ScopeGuard(engagement_name="t", allow=["10.10.10.*"], max_risk_level=ToolRiskLevel.POST_EXPLOIT)
    g.check_target("10.10.10.5")  # should not raise
    with pytest.raises(ScopeViolation):
        g.check_target("8.8.8.8")
