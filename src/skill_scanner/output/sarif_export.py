from __future__ import annotations

from pathlib import Path

from skill_scanner.models.reports import ScanReport

LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def export_sarif_report(report: ScanReport, output: str | None = None) -> str:
    results: list[dict[str, object]] = []
    rules: dict[str, dict[str, object]] = {}

    for item in report.reports:
        for finding in [*item.deterministic_findings, *item.ai_findings]:
            rule_id = f"skill-scanner/{finding.category.value}"
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
            }
            result: dict[str, object] = {
                "ruleId": rule_id,
                "level": LEVEL_MAP[finding.severity.value],
                "message": {"text": finding.description},
            }
            if finding.file_path:
                region = {"startLine": finding.line or 1}
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": region,
                        }
                    }
                ]
            results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skill-scanner",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    import json

    payload = json.dumps(sarif, indent=2)
    if output:
        Path(output).write_text(payload, encoding="utf-8")
    return payload
