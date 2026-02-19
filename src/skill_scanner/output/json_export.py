from __future__ import annotations

from pathlib import Path

from skill_scanner.models.reports import ScanReport


def export_json_report(report: ScanReport, output: str | None = None) -> str:
    payload = report.model_dump_json(indent=2)
    if output:
        Path(output).write_text(payload, encoding="utf-8")
    return payload
