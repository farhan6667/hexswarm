import pytest

from hexswarm.compliance import FRAMEWORKS, load_rules, map_findings, to_markdown
from hexswarm.memory.findings import Finding, FindingsStore


def store_with(*findings):
    s = FindingsStore(engagement_name="t")
    for f in findings:
        s.add(f)
    return s


def test_builtin_rules_load():
    rules = load_rules()
    assert len(rules) >= 8
    ids = {r.id for r in rules}
    assert "sql-injection" in ids
    assert "weak-transport-encryption" in ids


def test_sql_injection_maps_to_secure_coding_controls():
    s = store_with(Finding(phase="scan", tool_name="sql_injection_scan", target="http://x", summary="SQL injection in id"))
    mapped, unmapped = map_findings(s)
    assert len(mapped) == 1
    assert unmapped == []
    assert any("A.8.28" in c for c in mapped[0].iso27001)
    assert any("6.2.4" in c for c in mapped[0].pci_dss)


def test_keyword_match_beats_tool_only_match():
    # http_fingerprint appears in several rules' tool lists; a TLS keyword should route it
    # to the cryptography rule, not whichever tool-based rule is listed first.
    s = store_with(Finding(phase="scan", tool_name="http_fingerprint", target="x", summary="TLS 1.0 enabled, weak cipher"))
    mapped, _ = map_findings(s)
    assert mapped[0].rule_id == "weak-transport-encryption"
    assert any("A.8.24" in c for c in mapped[0].iso27001)


def test_exposed_network_service_does_not_fall_into_the_web_rule():
    # A Redis-on-open-port finding is a network exposure, not a web-app flaw. The web rule
    # must not carry a keyword broad enough ("exposed") to pull it in on a score tie.
    s = store_with(
        Finding(
            phase="recon",
            tool_name="port_scan",
            target="10.0.0.5",
            summary="Open port 6379 Redis exposed with no authentication",
        )
    )
    mapped, _ = map_findings(s)
    assert mapped[0].rule_id == "exposed-network-service"
    assert any("A.8.21" in c for c in mapped[0].iso27001)


def test_scanner_detecting_rce_is_not_treated_as_a_foothold():
    # A scan-phase nuclei finding whose output names "rce" has DETECTED a vulnerability, not
    # achieved a foothold. It must route to a vulnerability rule, never exploitation-foothold.
    s = store_with(
        Finding(
            phase="scan",
            tool_name="web_vuln_scan",
            target="http://x",
            summary="nuclei matched a template tagged rce on the target",
        )
    )
    mapped, _ = map_findings(s)
    assert mapped[0].rule_id != "exploitation-foothold"
    assert mapped[0].rule_id == "web-vulnerability"


def test_generic_flagged_wording_does_not_match_the_ai_rule():
    # "flagged" is ordinary scanner English; it must not pull a web finding into the
    # prompt-injection rule. That rule stays pinned to AI-specific wording and its own tool.
    s = store_with(
        Finding(
            phase="scan",
            tool_name="web_vuln_scan",
            target="http://x",
            summary="scanner flagged a suspicious response",
        )
    )
    mapped, _ = map_findings(s)
    assert mapped[0].rule_id != "prompt-injection-ai-app"


def test_real_exploit_phase_foothold_still_maps_to_foothold():
    # The phase gate must not break the real case: an exploit-phase foothold still maps.
    s = store_with(
        Finding(
            phase="exploit",
            tool_name="metasploit_module_run",
            target="10.0.0.5",
            summary="got a reverse shell on the target",
        )
    )
    mapped, _ = map_findings(s)
    assert mapped[0].rule_id == "exploitation-foothold"
    assert any("11.4.1" in c for c in mapped[0].pci_dss)


def test_unmatched_finding_is_unmapped_not_compliant():
    s = store_with(Finding(phase="recon", tool_name="whois_lookup", target="x", summary="registrar info"))
    mapped, unmapped = map_findings(s)
    assert mapped == []
    assert len(unmapped) == 1


def test_framework_filter_hides_the_other_set():
    s = store_with(Finding(phase="scan", tool_name="sql_injection_scan", target="x", summary="sqli"))
    mapped_iso, _ = map_findings(s, frameworks={"iso27001"})
    assert mapped_iso[0].iso27001
    assert mapped_iso[0].pci_dss == []  # pci hidden

    mapped_pci, _ = map_findings(s, frameworks={"pci-dss"})
    assert mapped_pci[0].pci_dss
    assert mapped_pci[0].iso27001 == []


def test_markdown_includes_disclaimer_and_counts():
    s = store_with(
        Finding(phase="scan", tool_name="sql_injection_scan", target="x", summary="sqli"),
        Finding(phase="recon", tool_name="whois_lookup", target="x", summary="registrar"),
    )
    md = to_markdown(s)
    assert "advisory mapping" in md.lower()
    assert "not a compliance assessment" in md.lower()
    assert "Mapped 1 of 2 findings" in md
    assert "Unmapped findings" in md


def test_load_rules_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_rules(tmp_path / "nope.yaml")


def test_frameworks_constant():
    assert FRAMEWORKS == {"iso27001", "pci-dss"}
