from __future__ import annotations

from collections import OrderedDict

from rich.console import Console

from skill_scanner.models.findings import Finding, Severity
from skill_scanner.models.reports import ScanReport, SkillReport

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _location(finding: Finding) -> str:
    if not finding.file_path:
        return "n/a"
    if finding.line:
        return f"{finding.file_path}:{finding.line}"
    return finding.file_path


def _top_findings(report: SkillReport, limit: int = 5) -> list[Finding]:
    findings = [*report.deterministic_findings, *report.ai_findings]
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_ORDER.get(item.severity, 0),
            item.category.value,
            item.title.lower(),
        ),
    )[:limit]


def _recommended_actions(report: SkillReport, limit: int = 3) -> list[str]:
    ordered: OrderedDict[str, None] = OrderedDict()
    for finding in _top_findings(report, limit=10):
        if finding.recommendation:
            ordered[finding.recommendation] = None
    return list(ordered.keys())[:limit]


def format_summary_report(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append("Skill Scanner Summary")
    lines.append(f"Scanned targets: {report.scanned_targets}")
    lines.append(
        "Overall: "
        f"critical={report.summary.get('critical', 0)}, "
        f"high={report.summary.get('high', 0)}, "
        f"medium={report.summary.get('medium', 0)}, "
        f"low={report.summary.get('low', 0)}, "
        f"clean={report.summary.get('clean', 0)}"
    )

    for index, item in enumerate(report.reports, start=1):
        lines.append("")
        lines.append(f"Target {index}: {item.target.entry_path}")
        lines.append(f"Risk: {item.risk_level.value.upper()} ({item.score:.2f})")
        total_findings = len(item.deterministic_findings) + len(item.ai_findings)
        lines.append(
            "Findings: "
            f"{total_findings} "
            f"(deterministic={len(item.deterministic_findings)}, ai={len(item.ai_findings)})"
        )

        if item.vt_report is None:
            lines.append("VirusTotal: not available")
        else:
            vt = item.vt_report
            vt_line = (
                "VirusTotal: "
                f"malicious={vt.malicious}, suspicious={vt.suspicious}, "
                f"undetected={vt.undetected}, harmless={vt.harmless}"
            )
            if vt.permalink:
                vt_line += f" | {vt.permalink}"
            lines.append(vt_line)

        if item.notes:
            lines.append("Notes:")
            for note_index, note in enumerate(item.notes, start=1):
                lines.append(f"{note_index}. {note}")
        else:
            lines.append("Notes: none")

        top_findings = _top_findings(item)
        if not top_findings:
            lines.append("Top findings: none")
        else:
            lines.append("Top findings:")
            for finding_index, finding in enumerate(top_findings, start=1):
                lines.append(
                    f"{finding_index}. [{finding.severity.value.upper()}] {finding.title} "
                    f"({finding.category.value}, source={finding.source})"
                )
                lines.append(f"   Location: {_location(finding)}")

        actions = _recommended_actions(item)
        if not actions:
            lines.append("Recommended actions: none")
        else:
            lines.append("Recommended actions:")
            for action_index, action in enumerate(actions, start=1):
                lines.append(f"{action_index}. {action}")

    return "\n".join(lines)


def render_summary_report(report: ScanReport, *, no_color: bool = False) -> str:
    payload = format_summary_report(report)
    Console(no_color=no_color).print(payload)
    return payload
