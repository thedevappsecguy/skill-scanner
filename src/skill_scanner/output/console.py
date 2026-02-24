from __future__ import annotations

from rich.console import Console
from rich.table import Table

from skill_scanner.models.reports import ScanReport


def render_console_report(report: ScanReport, *, no_color: bool = False) -> None:
    console = Console(no_color=no_color)
    table = Table(title="skill-scanner results")
    table.add_column("Target")
    table.add_column("Platform")
    table.add_column("Scope")
    table.add_column("Risk")
    table.add_column("Score", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("VT", justify="right")
    table.add_column("Notes", justify="right")

    for item in report.reports:
        vt = item.vt_report
        vt_count = 0 if vt is None else vt.malicious + vt.suspicious
        findings = len(item.deterministic_findings) + len(item.ai_findings)
        table.add_row(
            item.target.entry_path,
            item.target.platform.value,
            item.target.scope.value,
            item.risk_level.value.upper(),
            f"{item.score:.2f}",
            str(findings),
            str(vt_count),
            str(len(item.notes)),
        )

    console.print(table)
    console.print(f"Scanned targets: {report.scanned_targets}")
    console.print(f"Summary: {report.summary}")

    noted_items = [item for item in report.reports if item.notes]
    if noted_items:
        console.print("Notes:")
        for item in noted_items:
            console.print(f"- {item.target.entry_path}")
            for note in item.notes:
                console.print(f"  - {note}")
