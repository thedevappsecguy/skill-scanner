from __future__ import annotations

from skill_scanner.models.findings import Finding, Severity
from skill_scanner.models.reports import RiskLevel, SkillReport


def _severity_to_risk_level(severity: Severity) -> RiskLevel:
    mapping = {
        Severity.CRITICAL: RiskLevel.CRITICAL,
        Severity.HIGH: RiskLevel.HIGH,
        Severity.MEDIUM: RiskLevel.MEDIUM,
        Severity.LOW: RiskLevel.LOW,
        Severity.INFO: RiskLevel.CLEAN,
    }
    return mapping[severity]


def _risk_rank(risk_level: RiskLevel) -> int:
    order = {
        RiskLevel.CLEAN: 0,
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    return order[risk_level]


def findings_risk_level(findings: list[Finding]) -> RiskLevel:
    highest = RiskLevel.CLEAN
    for finding in findings:
        risk_level = _severity_to_risk_level(finding.severity)
        if _risk_rank(risk_level) > _risk_rank(highest):
            highest = risk_level
    return highest


def vt_report_risk_level(report: SkillReport) -> RiskLevel:
    if report.vt_report is None:
        return RiskLevel.CLEAN
    if report.vt_report.malicious >= 3:
        return RiskLevel.CRITICAL
    if report.vt_report.malicious > 0:
        return RiskLevel.HIGH
    if report.vt_report.suspicious > 0:
        return RiskLevel.MEDIUM
    return RiskLevel.CLEAN


def evaluate_risk(report: SkillReport) -> SkillReport:
    report.llm_risk_level = findings_risk_level(report.llm_findings)
    report.vt_risk_level = vt_report_risk_level(report)
    report.risk_level = max(report.llm_risk_level, report.vt_risk_level, key=_risk_rank)
    return report
