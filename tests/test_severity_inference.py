from hexswarm.agents.base import _infer_severity
from hexswarm.safety.guard import ToolRiskLevel
from hexswarm.tools.exploit import MetasploitModuleRun
from hexswarm.tools.privesc import LinuxPrivescEnum
from hexswarm.tools.recon import PortScan


def test_simulated_run_is_always_info_regardless_of_tier():
    tool = MetasploitModuleRun()
    assert tool.risk_level == ToolRiskLevel.EXPLOIT
    assert _infer_severity(tool, success=True, simulated=True) == "info"


def test_failed_real_run_is_info_not_escalated():
    tool = MetasploitModuleRun()
    assert _infer_severity(tool, success=False, simulated=False) == "info"


def test_successful_exploit_tier_run_is_flagged_high():
    tool = MetasploitModuleRun()
    assert _infer_severity(tool, success=True, simulated=False) == "high"


def test_successful_post_exploit_tier_run_is_flagged_critical():
    tool = LinuxPrivescEnum()
    assert _infer_severity(tool, success=True, simulated=False) == "critical"


def test_successful_read_only_recon_stays_info():
    tool = PortScan()
    assert tool.risk_level == ToolRiskLevel.ACTIVE_RECON
    assert _infer_severity(tool, success=True, simulated=False) == "info"
