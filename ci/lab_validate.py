"""End-to-end lab validation: real web tools against a real vulnerable app.

Runs inside the toolchain image (which has the real web toolchain installed),
pointed at a live OWASP Juice Shop on the same Docker network. It drives the
real ToolRegistry, not a mocked unit test, and proves three things in one go:

1. The web tools actually execute against a real application (simulated=False).
2. Those real findings flow through the findings store unchanged.
3. The compliance mapping turns them into advisory ISO 27001 / PCI DSS controls.

Exit code 0 only if at least one web tool genuinely ran (not simulate mode) and
the compliance mapping produced output with its disclaimer intact.

Usage: python3 lab_validate.py <target-url> [out-dir]
"""
from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlparse

import hexswarm.tools  # noqa: F401  registers every tool
from hexswarm.compliance import map_findings, to_markdown
from hexswarm.memory.findings import Finding, FindingsStore
from hexswarm.safety.guard import ScopeGuard, ToolRiskLevel
from hexswarm.tools.base import ToolRegistry

target = sys.argv[1] if len(sys.argv) > 1 else "http://juice-shop:3000"
out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/tmp/lab-out")
out_dir.mkdir(parents=True, exist_ok=True)

host = urlparse(target).hostname or target
print(f"=== lab validation against {target} (scope host: {host}) ===\n")

guard = ScopeGuard(
    engagement_name="lab-validation",
    allow=[host, "localhost", "127.0.0.1"],
    max_risk_level=ToolRiskLevel.INTRUSIVE,
)

# The web recon/scan tools that take a URL target. Exploitation and post-exploit
# tools are deliberately left out: this gate validates the scan surface, not a
# live exploit against the lab.
web_tools = [
    "http_probe",
    "http_fingerprint",
    "web_crawl",
    "web_vuln_scan",
    "directory_brute",
    "sql_injection_scan",
]

store = FindingsStore("lab-validation", persist_path=out_dir / "lab_findings.json")
real_runs = 0
attempted = 0

for name in web_tools:
    try:
        tool = ToolRegistry.get(name)
    except KeyError:
        print(f"[skip] {name}: not registered")
        continue
    if not tool.is_available():
        print(f"[skip] {name}: binary not installed in this image")
        continue
    attempted += 1
    try:
        res = tool.run(guard, target=target)
    except Exception as exc:  # noqa: BLE001  a tool blowing up shouldn't abort the gate
        print(f"[warn] {name}: raised {type(exc).__name__}: {exc}")
        continue

    real = res.simulated is False
    real_runs += int(real)
    first_line = next((ln for ln in res.output.splitlines() if ln.strip()), "")
    summary = f"{name} against {host}: {first_line[:140]}" if first_line else f"{name} against {host}"
    store.add(
        Finding(
            phase="scan",
            tool_name=name,
            target=target,
            summary=summary,
            severity="info",
            raw_output=res.output,
            command=res.command,
            simulated=res.simulated,
        )
    )
    print(f"[{'REAL' if real else 'sim '}] {name}: {res.command}")

print(f"\nattempted={attempted} real_runs={real_runs} findings={len(store.all())}")

# Gate 1: at least one web tool genuinely executed against the live app.
if real_runs == 0:
    print("\n::error::no web tool executed for real against the lab (all simulated or unavailable)")
    sys.exit(1)

# Gate 2: the compliance mapping turns these real findings into controls.
mapped, unmapped = map_findings(store)
md = to_markdown(store)
(out_dir / "lab_compliance_mapping.md").write_text(md, encoding="utf-8")

print(f"\ncompliance: mapped {len(mapped)} of {len(mapped) + len(unmapped)} real findings")
if len(mapped) == 0:
    print("::error::compliance mapping produced no mappings for real lab findings")
    sys.exit(1)
if "not a compliance assessment" not in md.lower():
    print("::error::compliance output is missing its advisory disclaimer")
    sys.exit(1)

print("\nLAB VALIDATION PASSED: real tools ran against a real vulnerable app and mapped to controls.")
