from __future__ import annotations

from collections import Counter

from skill_scanner.analyzers.ai_analyzer import analyze_with_ai
from skill_scanner.analyzers.vt_analyzer import scan_with_vt
from skill_scanner.models.findings import Category, Finding, Severity
from skill_scanner.models.reports import AIReport, ScanReport, SkillReport
from skill_scanner.models.targets import ScanTarget
from skill_scanner.providers.base import LLMProvider
from skill_scanner.scoring.risk import evaluate_risk


def run_scan(
    targets: list[ScanTarget],
    *,
    provider: LLMProvider | None,
    vt_api_key: str | None,
    enable_ai: bool,
    enable_vt: bool,
    vt_timeout_s: int = 300,
    vt_poll_interval_s: int = 10,
) -> ScanReport:
    reports: list[SkillReport] = []

    for target in targets:
        deterministic: list[Finding] = []

        vt_report = None
        if enable_vt and vt_api_key:
            vt_report = scan_with_vt(
                target,
                vt_api_key,
                timeout_s=vt_timeout_s,
                poll_interval_s=vt_poll_interval_s,
            )
            deterministic.extend(_vt_findings(vt_report))

        ai_report = AIReport(provider="disabled", model="n/a", findings=[])
        if enable_ai and provider is not None:
            ai_report = analyze_with_ai(target, provider, vt_report=vt_report)

        report = SkillReport(
            target=target,
            deterministic_findings=deterministic,
            ai_findings=ai_report.findings,
            vt_report=vt_report,
        )
        reports.append(evaluate_risk(report))

    summary_counter = Counter(item.risk_level.value for item in reports)
    summary = {key: summary_counter.get(key, 0) for key in ["critical", "high", "medium", "low", "clean"]}

    return ScanReport(
        scanned_targets=len(targets),
        reports=reports,
        summary=summary,
    )


def _vt_findings(vt_report: object) -> list[Finding]:
    from skill_scanner.models.reports import VTReport

    if not isinstance(vt_report, VTReport):
        return []

    findings: list[Finding] = []
    if vt_report.malicious > 0:
        severity = Severity.CRITICAL if vt_report.malicious >= 3 else Severity.HIGH
        findings.append(
            Finding(
                source="virustotal",
                category=Category.SUPPLY_CHAIN_RISK,
                severity=severity,
                title="VirusTotal detected malicious verdicts",
                description=(
                    "VirusTotal marked the uploaded artifact as malicious by "
                    f"{vt_report.malicious} engine(s)."
                ),
                recommendation=(
                    "Treat this artifact as high risk and review the VirusTotal report before use. "
                    f"Details: {vt_report.permalink or 'n/a'}"
                ),
            )
        )
    elif vt_report.suspicious > 0:
        findings.append(
            Finding(
                source="virustotal",
                category=Category.SUPPLY_CHAIN_RISK,
                severity=Severity.MEDIUM,
                title="VirusTotal detected suspicious verdicts",
                description=(
                    "VirusTotal marked the uploaded artifact as suspicious by "
                    f"{vt_report.suspicious} engine(s)."
                ),
                recommendation=(
                    "Review the VirusTotal detections before trusting this artifact. "
                    f"Details: {vt_report.permalink or 'n/a'}"
                ),
            )
        )

    return findings
