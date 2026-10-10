import pytest

from hexswarm.safety.guard import ScopeGuard, ScopeViolation, ToolRiskLevel


def make_guard(**overrides):
    defaults = {
        "engagement_name": "test-engagement",
        "allow": ["10.10.10.0/24", "*.example.com"],
        "deny": ["10.10.10.1"],
        "max_risk_level": ToolRiskLevel.INTRUSIVE,
    }
    defaults.update(overrides)
    return ScopeGuard(**defaults)


def test_allows_cidr_member():
    guard = make_guard()
    guard.check_target("10.10.10.50")  # should not raise


def test_allows_glob_hostname():
    guard = make_guard()
    guard.check_target("api.example.com")  # should not raise


def test_rejects_out_of_scope_target():
    guard = make_guard()
    with pytest.raises(ScopeViolation):
        guard.check_target("8.8.8.8")


def test_deny_overrides_allow():
    guard = make_guard()
    with pytest.raises(ScopeViolation):
        guard.check_target("10.10.10.1")


def test_risk_level_cap_blocks_higher_risk():
    guard = make_guard(max_risk_level=ToolRiskLevel.ACTIVE_RECON)
    with pytest.raises(ScopeViolation):
        guard.check_risk(ToolRiskLevel.EXPLOIT)


def test_risk_level_cap_allows_equal_or_lower():
    guard = make_guard(max_risk_level=ToolRiskLevel.ACTIVE_RECON)
    guard.check_risk(ToolRiskLevel.READ_ONLY)
    guard.check_risk(ToolRiskLevel.ACTIVE_RECON)


def test_authorize_combines_both_checks():
    guard = make_guard(max_risk_level=ToolRiskLevel.READ_ONLY)
    with pytest.raises(ScopeViolation):
        guard.authorize("10.10.10.50", ToolRiskLevel.INTRUSIVE)


def test_from_file_rejects_empty_allow(tmp_path):
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text("engagement_name: empty\nallow: []\n", encoding="utf-8")
    with pytest.raises(ValueError):
        ScopeGuard.from_file(scope_path)


def test_from_file_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        ScopeGuard.from_file(tmp_path / "does_not_exist.yaml")


def test_matches_url_target_against_domain_allow_rule():
    guard = make_guard(allow=["*.example.com"], deny=[])
    # web_vuln_scan / directory_brute / sql_injection_scan / http_fingerprint all pass full
    # URLs as their target; the scope entry is written as a domain glob, not a URL glob.
    guard.check_target("https://api.example.com/admin?x=1")  # should not raise


def test_matches_url_target_against_cidr_allow_rule():
    guard = make_guard(allow=["10.10.10.0/24"], deny=[])
    guard.check_target("http://10.10.10.50:8080/login")  # should not raise


def test_matches_url_target_rejects_out_of_scope_host():
    guard = make_guard(allow=["*.example.com"], deny=[])
    with pytest.raises(ScopeViolation):
        guard.check_target("https://evil.other.com/path")


def test_matches_url_target_still_applies_deny_rules():
    guard = make_guard(allow=["*.example.com"], deny=["admin.example.com"])
    with pytest.raises(ScopeViolation):
        guard.check_target("https://admin.example.com/login")


def test_from_file_loads_valid_scope(tmp_path):
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "engagement_name: lab\nallow:\n  - '192.168.1.0/24'\nmax_risk_level: exploit\n",
        encoding="utf-8",
    )
    guard = ScopeGuard.from_file(scope_path)
    assert guard.engagement_name == "lab"
    guard.check_target("192.168.1.42")
