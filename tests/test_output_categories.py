from __future__ import annotations

import json

from skill_scanner.models.findings import Category, Finding, Severity
from skill_scanner.models.reports import ScanReport, SkillReport
from skill_scanner.models.targets import Platform, ScanTarget, Scope, TargetKind
from skill_scanner.output.sarif_export import export_sarif_report
from skill_scanner.output.summary import format_summary_report


def _report_with_category(category: Category) -> ScanReport:
    target = ScanTarget(
        id="target-1",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path="/tmp/SKILL.md",
        root_dir="/tmp",
        files=[],
    )
    finding = Finding(
        source="openai",
        category=category,
        severity=Severity.HIGH,
        title="Test finding",
        description="Test description",
        file_path="/tmp/SKILL.md",
        line=3,
    )
    skill_report = SkillReport(
        target=target,
        vt_findings=[],
        llm_findings=[finding],
    )
    return ScanReport(
        scanned_targets=1,
        reports=[skill_report],
        summary={"critical": 0, "high": 1, "medium": 0, "low": 0, "clean": 0},
    )


def test_summary_uses_canonical_category_values() -> None:
    report = _report_with_category(Category.COMMAND_EXECUTION)
    payload = format_summary_report(report)
    assert "command_execution" in payload


def test_sarif_uses_canonical_category_values() -> None:
    report = _report_with_category(Category.COMMAND_EXECUTION)
    payload = export_sarif_report(report)
    parsed = json.loads(payload)
    rule_ids = [item["ruleId"] for item in parsed["runs"][0]["results"]]
    assert "skill-scanner/command_execution" in rule_ids
