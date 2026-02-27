from __future__ import annotations

from skill_scanner.models.findings import Severity
from skill_scanner.models.reports import RiskLevel, SkillReport
from skill_scanner.models.targets import Scope

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _findings_score(report: SkillReport) -> float:
    total = 0.0
    for finding in [*report.deterministic_findings, *report.ai_findings]:
        # VT detections are scored separately in _vt_score.
        if finding.source == "virustotal":
            continue
        total += SEVERITY_WEIGHTS.get(finding.severity, 0)
    return min(100.0, total)


def _vt_score(report: SkillReport) -> float:
    if report.vt_report is None:
        return 0.0
    return min(100.0, float(report.vt_report.malicious * 12 + report.vt_report.suspicious * 6))


def _scope_weight(scope: Scope) -> float:
    return {
        Scope.REPO: 1.0,
        Scope.USER: 1.2,
        Scope.SYSTEM: 1.3,
        Scope.EXTENSION: 1.25,
    }[scope]


def _risk_level(score: float) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 45:
        return RiskLevel.HIGH
    if score >= 20:
        return RiskLevel.MEDIUM
    if score > 0:
        return RiskLevel.LOW
    return RiskLevel.CLEAN


def evaluate_risk(report: SkillReport) -> SkillReport:
    ai_raw_score = _findings_score(report)
    vt_raw_score = _vt_score(report)
    scope_weight = _scope_weight(report.target.scope)
    ai_score = min(100.0, ai_raw_score * scope_weight)
    vt_score = min(100.0, vt_raw_score * scope_weight)

    combined = max(ai_score, vt_score) * 0.6 + min(ai_score, vt_score) * 0.4

    report.ai_score = round(ai_score, 2)
    report.ai_risk_level = _risk_level(report.ai_score)
    report.vt_score = round(vt_score, 2)
    report.vt_risk_level = _risk_level(report.vt_score)

    report.score = round(min(100.0, combined), 2)
    report.risk_level = _risk_level(report.score)
    return report
