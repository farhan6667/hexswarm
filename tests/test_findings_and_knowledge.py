from hexswarm.memory.findings import Finding, FindingsStore
from hexswarm.memory.knowledge import KnowledgeBase


def test_findings_store_add_and_query():
    store = FindingsStore(engagement_name="t")
    store.add(Finding(phase="recon", tool_name="port_scan", target="1.2.3.4", summary="open 22,80"))
    store.add(Finding(phase="scan", tool_name="web_vuln_scan", target="1.2.3.4", summary="xss found", severity="high"))

    assert len(store.all()) == 2
    assert len(store.by_phase("recon")) == 1
    assert len(store.by_severity("high")) == 1
    assert "port_scan" in store.summary_text()


def test_findings_store_persists_to_disk(tmp_path):
    path = tmp_path / "findings.json"
    store = FindingsStore(engagement_name="t", persist_path=path)
    store.add(Finding(phase="recon", tool_name="whois_lookup", target="example.com", summary="registrar: x"))

    assert path.exists()
    reloaded = FindingsStore(engagement_name="t", persist_path=path)
    assert len(reloaded.all()) == 1
    assert reloaded.all()[0].tool_name == "whois_lookup"


def test_findings_store_empty_summary():
    store = FindingsStore(engagement_name="t")
    assert "No findings" in store.summary_text()


def test_knowledge_base_lookup_matches_service():
    kb = KnowledgeBase()
    hints = kb.lookup("220 vsFTPd 2.3.4 service ready")
    assert any(h.service == "ftp" for h in hints)


def test_knowledge_base_lookup_no_match():
    kb = KnowledgeBase()
    assert kb.lookup("some completely unrelated banner string") == []


def test_knowledge_base_custom_path(tmp_path):
    custom = tmp_path / "hints.yaml"
    custom.write_text("widgetd:\n  checklist:\n    - 'check default creds'\n  references: []\n", encoding="utf-8")
    kb = KnowledgeBase(path=custom)
    hits = kb.lookup("running widgetd 1.0")
    assert len(hits) == 1
    assert hits[0].checklist == ["check default creds"]
