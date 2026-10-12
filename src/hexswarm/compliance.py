"""Map engagement findings to the compliance controls they relate to.

This is an advisory mapping layer, not a compliance verdict and not a
certification. It takes the findings HexSwarm produced and, for each one,
points to the ISO 27001:2022 Annex A controls and PCI DSS 4.0 requirements
that finding touches, so a pentest report becomes something a compliance or
audit team can act on. Whether an environment actually passes a framework is
an assessor's judgement based on scope, policies, and evidence well beyond a
single pentest, and this module never claims otherwise.

Honest limits, stated up front and repeated in the output:
- A mapping means "this finding relates to that control", not "you fail it".
- A finding with no mapping is not "compliant"; it just has no rule here yet.
- Control identifiers follow ISO/IEC 27001:2022 Annex A and PCI DSS v4.0;
  verify the exact clause against the current standard before formal use.
- This maps technical findings only. Governance, policy, and process controls
  that a pentest never touches are out of scope and absent by design.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from hexswarm.memory.findings import Finding, FindingsStore

_DEFAULT_RULES = Path(__file__).parent / "data" / "compliance" / "mappings.yaml"

FRAMEWORKS = {"iso27001", "pci-dss"}


@dataclass
class MappingRule:
    id: str
    match_tools: list[str] = field(default_factory=list)
    match_keywords: list[str] = field(default_factory=list)
    match_phases: list[str] = field(default_factory=list)
    iso27001: list[str] = field(default_factory=list)
    pci_dss: list[str] = field(default_factory=list)
    rationale: str = ""

    def match_score(self, finding: Finding) -> int:
        """0 = no match, 1 = matched on tool only, 2 = matched on a keyword.

        A keyword match is more specific than a broad tool match (several rules can list
        the same tool), so it scores higher and wins when rules compete for one finding.

        `match_phases`, when set, is a hard gate: the rule only applies to findings from
        those engagement phases, whatever the keywords say. A scanner naming "rce" in its
        output is a vulnerability it detected, not a foothold it achieved, so the
        post-access rules (foothold, privesc) are pinned to the exploit/privesc phases and
        a scan-phase finding falls through to the vulnerability rules instead.
        """
        if self.match_phases and finding.phase not in self.match_phases:
            return 0
        text = f"{finding.summary} {finding.raw_output}".lower()
        if any(kw.lower() in text for kw in self.match_keywords):
            return 2
        if finding.tool_name in self.match_tools:
            return 1
        return 0

    def matches(self, finding: Finding) -> bool:
        return self.match_score(finding) > 0


@dataclass
class MappedFinding:
    finding: Finding
    rule_id: str
    iso27001: list[str]
    pci_dss: list[str]
    rationale: str


def load_rules(path: str | Path | None = None) -> list[MappingRule]:
    path = Path(path) if path else _DEFAULT_RULES
    if not path.exists():
        raise FileNotFoundError(f"Compliance mapping rules not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [
        MappingRule(
            id=r["id"],
            match_tools=list(r.get("match_tools", [])),
            match_keywords=list(r.get("match_keywords", [])),
            match_phases=list(r.get("match_phases", [])),
            iso27001=list(r.get("iso27001", [])),
            pci_dss=list(r.get("pci_dss", [])),
            rationale=r.get("rationale", ""),
        )
        for r in data.get("rules", [])
    ]


def map_findings(
    findings: FindingsStore,
    frameworks: set[str] | None = None,
    rules: list[MappingRule] | None = None,
) -> tuple[list[MappedFinding], list[Finding]]:
    """Returns (mapped findings, unmapped findings).

    `frameworks` filters which control sets appear (iso27001 and/or pci-dss);
    None means both. A finding can match more than one rule; the first matching
    rule wins, to keep each finding's mapping single and readable.
    """
    frameworks = frameworks or set(FRAMEWORKS)
    rules = rules if rules is not None else load_rules()

    mapped: list[MappedFinding] = []
    unmapped: list[Finding] = []
    for finding in findings.all():
        # Pick the best-matching rule: a keyword match (score 2) beats a broad tool-only
        # match (score 1), so a TLS finding maps to the crypto rule rather than whichever
        # tool-based rule happens to list the same tool first.
        best = max(rules, key=lambda r: r.match_score(finding), default=None)
        rule = best if best is not None and best.match_score(finding) > 0 else None
        if rule is None:
            unmapped.append(finding)
            continue
        mapped.append(
            MappedFinding(
                finding=finding,
                rule_id=rule.id,
                iso27001=rule.iso27001 if "iso27001" in frameworks else [],
                pci_dss=rule.pci_dss if "pci-dss" in frameworks else [],
                rationale=rule.rationale,
            )
        )
    return mapped, unmapped


_DISCLAIMER = (
    "This is an advisory mapping of technical findings to the controls they relate to, "
    "not a compliance assessment. It does not determine whether the environment passes "
    "ISO 27001 or PCI DSS; that is an assessor's judgement based on scope, policies, and "
    "evidence beyond this pentest. Unmapped findings are not 'compliant', only unmatched. "
    "Verify every control identifier against the current published standard before formal use."
)


def to_markdown(
    findings: FindingsStore, frameworks: set[str] | None = None, rules: list[MappingRule] | None = None
) -> str:
    frameworks = frameworks or set(FRAMEWORKS)
    mapped, unmapped = map_findings(findings, frameworks, rules)

    show_iso = "iso27001" in frameworks
    show_pci = "pci-dss" in frameworks
    header = ["Finding", "Tier/Severity"]
    if show_iso:
        header.append("ISO 27001:2022")
    if show_pci:
        header.append("PCI DSS 4.0")

    lines = [
        "# Compliance mapping",
        "",
        f"_{_DISCLAIMER}_",
        "",
        f"Mapped {len(mapped)} of {len(mapped) + len(unmapped)} findings.",
        "",
        "| " + " | ".join(header) + " |",
        "|" + "|".join(["---"] * len(header)) + "|",
    ]
    for m in mapped:
        row = [
            f"{m.finding.tool_name} on {m.finding.target}",
            f"{m.finding.phase}/{m.finding.severity}",
        ]
        if show_iso:
            row.append("; ".join(m.iso27001) or "-")
        if show_pci:
            row.append("; ".join(m.pci_dss) or "-")
        lines.append("| " + " | ".join(c.replace("|", "\\|") for c in row) + " |")

    if unmapped:
        lines.append("")
        lines.append("## Unmapped findings (no rule matched, not a compliance judgement)")
        lines.append("")
        for f in unmapped:
            lines.append(f"- {f.tool_name} on {f.target}: {f.summary[:120]}")

    return "\n".join(lines) + "\n"
