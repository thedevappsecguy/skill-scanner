from __future__ import annotations

import asyncio

from skill_scanner.analyzers import pipeline as pipeline_module
from skill_scanner.analyzers.ai_analyzer import PayloadBuildResult
from skill_scanner.analyzers.pipeline import run_scan
from skill_scanner.discovery.finder import discover_targets
from skill_scanner.models.reports import AIReport, SkillReport, VTReport, VTScanResult
from skill_scanner.models.targets import Platform, ScanTarget, Scope, TargetKind


def test_pipeline_deterministic_only_runs(fixture_root) -> None:
    targets = discover_targets(path=str(fixture_root), platform=Platform.ALL)
    report = run_scan(targets, provider=None, vt_api_key=None, enable_ai=False, enable_vt=False)
    assert report.scanned_targets >= 1


def test_pipeline_adds_vt_derived_findings(monkeypatch, fixture_root) -> None:
    targets = discover_targets(path=str(fixture_root / "clean_skill"), platform=Platform.ALL)

    async def _fake_scan_with_vt(*_args, **_kwargs) -> VTScanResult:
        return VTScanResult(
            report=VTReport(
                sha256="abc",
                malicious=2,
                suspicious=0,
                harmless=0,
                undetected=10,
                permalink="https://example.test/vt",
            )
        )

    monkeypatch.setattr(pipeline_module, "scan_with_vt", _fake_scan_with_vt)

    report = run_scan(targets, provider=None, vt_api_key="vt-key", enable_ai=False, enable_vt=True)
    assert any(
        finding.source == "virustotal"
        for finding in report.reports[0].deterministic_findings
    )


def test_pipeline_passes_vt_context_to_ai(monkeypatch, fixture_root) -> None:
    targets = discover_targets(path=str(fixture_root / "clean_skill"), platform=Platform.ALL)

    async def _fake_scan_with_vt(*_args, **_kwargs) -> VTScanResult:
        return VTScanResult(
            report=VTReport(
                sha256="abc",
                malicious=1,
                suspicious=0,
                harmless=0,
                undetected=5,
                permalink="https://example.test/vt",
            )
        )

    monkeypatch.setattr(pipeline_module, "scan_with_vt", _fake_scan_with_vt)

    captured: dict[str, object] = {}

    async def _fake_analyze_with_ai(target, provider, vt_report=None):
        captured["vt_report"] = vt_report
        return (
            AIReport(provider="test", model="test", findings=[]),
            PayloadBuildResult(payload="payload", included_files=1),
        )

    monkeypatch.setattr(pipeline_module, "analyze_with_ai", _fake_analyze_with_ai)

    report = run_scan(targets, provider=object(), vt_api_key="vt-key", enable_ai=True, enable_vt=True)
    assert report.scanned_targets == 1
    assert isinstance(captured.get("vt_report"), VTReport)


def test_pipeline_parallelism_preserves_input_order(monkeypatch) -> None:
    targets = [
        ScanTarget(
            id=f"target-{index}",
            kind=TargetKind.SKILL,
            platform=Platform.ALL,
            scope=Scope.REPO,
            entry_path=f"/tmp/{index}/SKILL.md",
            root_dir=f"/tmp/{index}",
            files=[],
        )
        for index in range(3)
    ]

    async def _fake_scan_target(target, **_kwargs) -> SkillReport:
        delay = 0.03 if target.id.endswith("0") else 0.01
        await asyncio.sleep(delay)
        return SkillReport(target=target)

    monkeypatch.setattr(pipeline_module, "_scan_target", _fake_scan_target)

    report = run_scan(targets, provider=None, vt_api_key=None, enable_ai=False, enable_vt=False, jobs=3)
    assert [item.target.id for item in report.reports] == [item.id for item in targets]


def test_pipeline_adds_notes_for_truncation_and_ai_errors(monkeypatch, fixture_root) -> None:
    targets = discover_targets(path=str(fixture_root / "clean_skill"), platform=Platform.ALL)

    async def _fake_analyze_with_ai(*_args, **_kwargs):
        return (
            AIReport(provider="openai", model="gpt-5.2", findings=[], error="mock failure"),
            PayloadBuildResult(
                payload="payload",
                included_files=1,
                skipped_due_to_limit=["large.md"],
            ),
        )

    monkeypatch.setattr(pipeline_module, "analyze_with_ai", _fake_analyze_with_ai)

    report = run_scan(targets, provider=object(), vt_api_key=None, enable_ai=True, enable_vt=False)
    assert any("AI payload truncated" in note for note in report.reports[0].notes)
    assert any("AI analysis" in note for note in report.reports[0].notes)
