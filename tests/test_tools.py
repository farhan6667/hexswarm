from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel
from hexswarm.tools.base import ToolRegistry
from hexswarm.tools.recon import PortScan


def guard():
    return ScopeGuard(
        engagement_name="t",
        allow=["scanme.nmap.org", "10.10.10.0/24"],
        max_risk_level=ToolRiskLevel.POST_EXPLOIT,
    )


def test_registry_contains_expected_tools():
    names = ToolRegistry.all().keys()
    for expected in [
        "whois_lookup", "dns_enum", "port_scan", "http_fingerprint",
        "web_vuln_scan", "directory_brute", "sql_injection_scan", "password_brute_force",
        "exploit_search", "metasploit_module_run",
        "linux_privesc_enum", "windows_privesc_enum",
    ]:
        assert expected in names


def test_registry_contains_projectdiscovery_recon_tools():
    names = ToolRegistry.all()
    for expected in ["http_probe", "fast_port_scan", "web_crawl", "dns_resolve"]:
        assert expected in names
        assert names[expected].risk_level in (ToolRiskLevel.READ_ONLY, ToolRiskLevel.ACTIVE_RECON)


def test_projectdiscovery_tools_build_commands():
    from hexswarm.tools.base import ToolRegistry as TR
    assert TR.get("http_probe").build_command(target="https://example.com")[0] == "httpx"
    assert TR.get("fast_port_scan").build_command(target="10.0.0.0/24")[0] == "naabu"
    assert TR.get("web_crawl").build_command(target="https://example.com")[0] == "katana"
    assert TR.get("dns_resolve").build_command(target="example.com")[0] == "dnsx"


def test_registry_contains_adopted_tools():
    names = ToolRegistry.all()
    for expected in ["subdomain_enum", "osint_harvest", "subdomain_takeover", "xss_scan", "llm_scan"]:
        assert expected in names


def test_adopted_tools_build_commands(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    subs_file = tmp_path / "subs.txt"
    subs_file.write_text("sub.example.com\n")
    reg = ToolRegistry
    assert reg.get("subdomain_enum").build_command(target="example.com") == [
        "amass", "enum", "-passive", "-d", "example.com",
    ]
    assert reg.get("osint_harvest").build_command(target="example.com")[:3] == [
        "theHarvester", "-d", "example.com",
    ]
    assert reg.get("subdomain_takeover").build_command(target=str(subs_file)) == [
        "SubOver", "-l", str(subs_file.resolve()),
    ]
    assert reg.get("xss_scan").build_command(target="http://x/?q=1")[:3] == [
        "dalfox", "url", "http://x/?q=1",
    ]
    llm = reg.get("llm_scan").build_command(target="gpt-4o-mini")
    assert llm[0] == "garak" and "--model_name" in llm and "gpt-4o-mini" in llm


def test_llm_scan_is_ai_security_and_skips_host_scope():
    tool = ToolRegistry.get("llm_scan")
    assert tool.category == "ai-security"
    # Its target is a model name, not a network host, so it must not go through host scope matching.
    assert tool.requires_scope_check is False


def test_subdomain_takeover_skips_host_scope():
    # Its target is a staged file path, not a host, so host scope matching is bypassed.
    assert ToolRegistry.get("subdomain_takeover").requires_scope_check is False


def test_adopted_tool_simulates_when_binary_missing(monkeypatch):
    tool = ToolRegistry.get("subdomain_enum")
    monkeypatch.setattr(tool, "is_available", lambda: False)
    result = tool.run(guard(), target="scanme.nmap.org")
    assert result.simulated is True
    assert "amass" in result.output


def test_port_scan_builds_expected_command():
    tool = PortScan()
    cmd = tool.build_command(target="scanme.nmap.org", ports="22,80")
    assert cmd[0] == "nmap"
    assert "scanme.nmap.org" in cmd
    assert "-p" in cmd and "22,80" in cmd


def test_tool_runs_in_simulate_mode_when_binary_missing(monkeypatch):
    tool = PortScan()
    monkeypatch.setattr(tool, "is_available", lambda: False)
    result = tool.run(guard(), target="scanme.nmap.org")
    assert result.simulated is True
    assert result.success is True
    assert "SIMULATED" in result.output
    assert "nmap" in result.output


def test_tool_blocks_out_of_scope_target():
    from hexswarm.safety.guard import ScopeViolation

    tool = PortScan()
    with __import__("pytest").raises(ScopeViolation):
        tool.run(guard(), target="8.8.8.8")


def test_to_openai_schema_shape():
    tool = PortScan()
    schema = tool.to_openai_schema()
    assert schema["type"] == "function"
    assert schema["function"]["name"] == "port_scan"
    assert "target" in schema["function"]["parameters"]["properties"]
