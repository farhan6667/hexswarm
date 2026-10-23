import base64

from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel
from hexswarm.tools.base import ToolRegistry
from hexswarm.tools.ctf import DecodeText


def guard(max_risk=ToolRiskLevel.READ_ONLY):
    # An intentionally narrow allow list: proves ctf tools never consult it.
    return ScopeGuard(engagement_name="t", allow=["not-a-real-pattern"], max_risk_level=max_risk)


def test_ctf_tools_registered_under_ctf_category():
    ctf_tools = ToolRegistry.for_category("ctf")
    for expected in ["file_identify", "string_extract", "binwalk_scan", "hash_identify", "decode_text"]:
        assert expected in ctf_tools
        assert ctf_tools[expected].category == "ctf"


def test_ctf_tools_excluded_from_pentest_phase_lookup():
    recon_tools = ToolRegistry.for_phase([ToolRiskLevel.READ_ONLY, ToolRiskLevel.ACTIVE_RECON])
    assert "decode_text" not in recon_tools
    assert "whois_lookup" in recon_tools


def test_decode_text_reports_available_without_a_binary():
    # binary="" for local_only tools; is_available() must not do shutil.which("") and
    # misreport a tool that never shells out as "missing".
    tool = DecodeText()
    assert tool.is_available() is True


def test_decode_text_never_consults_the_scope_allow_list():
    tool = DecodeText()
    secret = base64.b64encode(b"flag{test}").decode()
    # allow list above is garbage on purpose; this must not raise ScopeViolation.
    result = tool.run(guard(), target=secret)
    assert result.simulated is False
    assert "flag{test}" in result.output


def test_decode_text_blocked_above_max_risk_level():
    tool = DecodeText()
    # There is no risk tier below READ_ONLY, so this can't be tested by lowering max_risk_level
    # below it; instead confirm check_risk() is actually being called by raising it on a
    # deliberately impossible comparison via a monkeypatched tool risk level.
    import hexswarm.tools.ctf as ctf_module

    original = ctf_module.DecodeText.risk_level
    try:
        ctf_module.DecodeText.risk_level = ToolRiskLevel.EXPLOIT
        narrow = ScopeGuard(engagement_name="t", allow=["x"], max_risk_level=ToolRiskLevel.READ_ONLY)
        try:
            tool.run(narrow, target="aGVsbG8=")
            raised = False
        except ScopeViolation:
            raised = True
        assert raised is True
    finally:
        ctf_module.DecodeText.risk_level = original


def test_decode_text_base64_roundtrip():
    tool = DecodeText()
    secret = base64.b64encode(b"HexSwarm rocks").decode()
    result = tool.run(guard(), target=secret)
    assert "[base64] HexSwarm rocks" in result.output


def test_decode_text_hex_roundtrip():
    tool = DecodeText()
    result = tool.run(guard(), target="68656c6c6f")
    assert "[hex] hello" in result.output


def test_decode_text_no_percent_no_spurious_url_decoding():
    tool = DecodeText()
    result = tool.run(guard(), target="plainflag")
    assert "[url]" not in result.output


def test_decode_text_reports_when_nothing_decodes():
    tool = DecodeText()
    # No letters at all: rot13 becomes a no-op (filtered as uninformative, same as url
    # unquote on a string with no %-escapes), and the symbols aren't valid base64/hex input.
    result = tool.run(guard(), target="!!!1234567890###")
    assert "No printable result" in result.output


def test_file_identify_builds_expected_command(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    sample = tmp_path / "challenge.bin"
    sample.write_bytes(b"\x7fELF")
    tool = ToolRegistry.get("file_identify")
    cmd = tool.build_command(target=str(sample))
    assert cmd[0] == "file"
    assert str(sample.resolve()) in cmd


def test_file_identify_simulates_when_binary_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSWARM_WORK_DIR", str(tmp_path))
    sample = tmp_path / "challenge.bin"
    sample.write_bytes(b"\x7fELF")
    tool = ToolRegistry.get("file_identify")
    monkeypatch.setattr(tool, "is_available", lambda: False)
    result = tool.run(guard(), target=str(sample))
    assert result.simulated is True
