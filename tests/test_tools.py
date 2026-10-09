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
