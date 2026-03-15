from __future__ import annotations

from skill_scanner.models.findings import Category, Finding, Severity
from skill_scanner.models.reports import SkillReport, VTReport
from skill_scanner.models.targets import Platform, ScanTarget, Scope, TargetKind
from skill_scanner.scoring.risk import evaluate_risk


def _target() -> ScanTarget:
    return ScanTarget(
        id="1",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path="/tmp/SKILL.md",
        root_dir="/tmp",
        files=[],
    )


def test_critical_llm_finding_drives_overall_risk() -> None:
    report = SkillReport(
        target=_target(),
        llm_findings=[
            Finding(
                source="openai",
                category=Category.PROMPT_INJECTION,
                severity=Severity.CRITICAL,
                title="Critical prompt injection",
                description="High-confidence exploit path.",
            )
        ],
    )

    scored = evaluate_risk(report)
    assert scored.llm_risk_level.value == "critical"
    assert scored.vt_risk_level.value == "clean"
    assert scored.risk_level.value == "critical"


def test_vt_critical_overrides_weaker_llm_signal() -> None:
    report = SkillReport(
        target=_target(),
        vt_findings=[
            Finding(
                source="virustotal",
                category=Category.SUPPLY_CHAIN,
                severity=Severity.CRITICAL,
                title="VT critical hit",
                description="VT marked the artifact malicious.",
            )
        ],
        llm_findings=[
            Finding(
                source="openai",
                category=Category.CONFIGURATION_RISK,
                severity=Severity.LOW,
                title="Low-risk note",
                description="Low-severity finding.",
            )
        ],
        vt_report=VTReport(sha256="abc", malicious=3, suspicious=0, harmless=0, undetected=10),
    )

    scored = evaluate_risk(report)
    assert scored.llm_risk_level.value == "low"
    assert scored.vt_risk_level.value == "critical"
    assert scored.risk_level.value == "critical"


def test_vt_malicious_thresholds_map_to_expected_risk_levels() -> None:
    cases = [
        (0, 1, "medium"),
        (1, 0, "high"),
        (2, 0, "high"),
        (3, 0, "critical"),
    ]

    for malicious, suspicious, expected in cases:
        report = SkillReport(
            target=_target(),
            vt_report=VTReport(
                sha256="abc",
                malicious=malicious,
                suspicious=suspicious,
                harmless=0,
                undetected=10,
            ),
        )
        scored = evaluate_risk(report)
        assert scored.vt_risk_level.value == expected
        assert scored.risk_level.value == expected


def test_info_only_llm_findings_do_not_raise_risk() -> None:
    report = SkillReport(
        target=_target(),
        llm_findings=[
            Finding(
                source="openai",
                category=Category.CONFIGURATION_RISK,
                severity=Severity.INFO,
                title="Informational note",
                description="No actionable risk.",
            )
        ],
    )

    scored = evaluate_risk(report)
    assert scored.llm_risk_level.value == "clean"
    assert scored.vt_risk_level.value == "clean"
    assert scored.risk_level.value == "clean"
