from __future__ import annotations

from skill_scanner.models.findings import Category, Finding, Severity
from skill_scanner.models.reports import SkillReport, VTReport
from skill_scanner.models.targets import Platform, ScanTarget, Scope, TargetKind
from skill_scanner.scoring.risk import evaluate_risk


def test_risk_increases_with_high_findings() -> None:
    target = ScanTarget(
        id="1",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path="/tmp/SKILL.md",
        root_dir="/tmp",
        files=[],
    )
    report = SkillReport(
        target=target,
        deterministic_findings=[
            Finding(
                source="deterministic",
                category=Category.PROMPT_INJECTION,
                severity=Severity.HIGH,
                title="bad",
                description="bad",
            )
        ],
    )
    scored = evaluate_risk(report)
    assert scored.score > 0
    assert scored.risk_level.value in {"medium", "high", "critical", "low"}
    assert scored.ai_score > 0
    assert scored.ai_risk_level.value in {"medium", "high", "critical", "low"}
    assert scored.vt_score == 0.0
    assert scored.vt_risk_level.value == "clean"


def test_vt_source_findings_not_double_counted() -> None:
    target = ScanTarget(
        id="1",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path="/tmp/SKILL.md",
        root_dir="/tmp",
        files=[],
    )
    report = SkillReport(
        target=target,
        deterministic_findings=[
            Finding(
                source="virustotal",
                category=Category.SUPPLY_CHAIN_RISK,
                severity=Severity.HIGH,
                title="VT hit",
                description="VT marked malicious",
            )
        ],
        vt_report=VTReport(sha256="abc", malicious=1, suspicious=0, harmless=0, undetected=10),
    )

    scored = evaluate_risk(report)
    # If VT finding were double-counted, this value would be > 12.
    assert scored.score == 7.2
    assert scored.ai_score == 0.0
    assert scored.ai_risk_level.value == "clean"
    assert scored.vt_score == 12.0
    assert scored.vt_risk_level.value == "low"
