"""Machine-readable exports of an engagement's findings.

Markdown is for humans; this is for the rest of the toolchain. SARIF (Static
Analysis Results Interchange Format) is the format GitHub's code-scanning /
Security tab ingests natively, so a HexSwarm run can drop findings straight
into a repo's security view or a CI gate. A plain structured-JSON export is
also provided for anything that isn't GitHub.

Severity mapping: HexSwarm's severities map to SARIF's three levels, since
SARIF only has error/warning/note. critical+high -> error, medium -> warning,
everything else -> note.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from hexswarm import __version__

if TYPE_CHECKING:
    from hexswarm.memory.findings import FindingsStore

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def findings_to_sarif_dict(findings: FindingsStore, target: str) -> dict[str, Any]:
    """Builds a SARIF 2.1.0 document from the findings store."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings.all():
        rule_id = f"hexswarm/{f.phase}/{f.tool_name}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"{f.tool_name}",
                "shortDescription": {"text": f"{f.tool_name} ({f.phase} phase)"},
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f.summary},
                "properties": {
                    "phase": f.phase,
                    "severity": f.severity,
                    "target": f.target,
                    "timestamp": f.timestamp,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.target or target}
                        }
                    }
                ],
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "HexSwarm",
                        "informationUri": "https://github.com/farhan6667/hexswarm",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def findings_to_sarif(findings: FindingsStore, target: str) -> str:
    return json.dumps(findings_to_sarif_dict(findings, target), indent=2)


def findings_to_json(findings: FindingsStore) -> str:
    """Plain structured JSON export: every finding with its full fields."""
    return json.dumps(
        {
            "engagement_name": findings.engagement_name,
            "findings": [f.to_dict() for f in findings.all()],
        },
        indent=2,
    )
