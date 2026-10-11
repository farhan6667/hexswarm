import json

from hexswarm.memory.findings import Finding, FindingsStore
from hexswarm.reporting import findings_to_json, findings_to_sarif, findings_to_sarif_dict


def populated_store():
    store = FindingsStore(engagement_name="demo")
    store.add(Finding(phase="recon", tool_name="port_scan", target="10.0.0.5", summary="22,80 open", severity="info"))
    store.add(Finding(phase="scan", tool_name="web_vuln_scan", target="http://10.0.0.5", summary="XSS", severity="high"))
    store.add(Finding(phase="exploit", tool_name="metasploit_module_run", target="10.0.0.5", summary="shell", severity="critical"))
    return store


def test_sarif_has_valid_top_level_shape():
    doc = findings_to_sarif_dict(populated_store(), "10.0.0.5")
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"] == "HexSwarm"


def test_sarif_maps_severity_to_levels():
    doc = findings_to_sarif_dict(populated_store(), "10.0.0.5")
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["hexswarm/recon/port_scan"] == "note"       # info -> note
    assert levels["hexswarm/scan/web_vuln_scan"] == "error"    # high -> error
    assert levels["hexswarm/exploit/metasploit_module_run"] == "error"  # critical -> error


def test_sarif_deduplicates_rules():
    store = FindingsStore(engagement_name="demo")
    store.add(Finding(phase="recon", tool_name="port_scan", target="a", summary="s1"))
    store.add(Finding(phase="recon", tool_name="port_scan", target="b", summary="s2"))
    doc = findings_to_sarif_dict(store, "x")
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1  # one rule, two results
    assert len(doc["runs"][0]["results"]) == 2


def test_sarif_is_valid_json():
    text = findings_to_sarif(populated_store(), "10.0.0.5")
    parsed = json.loads(text)
    assert parsed["version"] == "2.1.0"


def test_json_export_roundtrips():
    text = findings_to_json(populated_store())
    parsed = json.loads(text)
    assert parsed["engagement_name"] == "demo"
    assert len(parsed["findings"]) == 3
    assert parsed["findings"][0]["tool_name"] == "port_scan"


def test_empty_store_produces_valid_empty_sarif():
    doc = findings_to_sarif_dict(FindingsStore(engagement_name="empty"), "x")
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
