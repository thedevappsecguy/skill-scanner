from __future__ import annotations

from skill_scanner.analyzers import pipeline as pipeline_module
from skill_scanner.analyzers.pipeline import run_scan
from skill_scanner.discovery.finder import discover_targets
from skill_scanner.models.reports import AIReport, VTReport
from skill_scanner.models.targets import Platform


def test_pipeline_deterministic_only_runs(fixture_root) -> None:
    targets = discover_targets(path=str(fixture_root), platform=Platform.ALL)
    report = run_scan(targets, provider=None, vt_api_key=None, enable_ai=False, enable_vt=False)
    assert report.scanned_targets >= 1


def test_pipeline_adds_vt_derived_findings(monkeypatch, fixture_root) -> None:
    targets = discover_targets(path=str(fixture_root / "clean_skill"), platform=Platform.ALL)

    monkeypatch.setattr(
        pipeline_module,
        "scan_with_vt",
        lambda *_args, **_kwargs: VTReport(
            sha256="abc",
            malicious=2,
            suspicious=0,
            harmless=0,
            undetected=10,
            permalink="https://example.test/vt",
        ),
    )

    report = run_scan(targets, provider=None, vt_api_key="vt-key", enable_ai=False, enable_vt=True)
    assert any(
        finding.source == "virustotal"
        for finding in report.reports[0].deterministic_findings
    )


def test_pipeline_passes_vt_context_to_ai(monkeypatch, fixture_root) -> None:
    targets = discover_targets(path=str(fixture_root / "clean_skill"), platform=Platform.ALL)

    monkeypatch.setattr(
        pipeline_module,
        "scan_with_vt",
        lambda *_args, **_kwargs: VTReport(
            sha256="abc",
            malicious=1,
            suspicious=0,
            harmless=0,
            undetected=5,
            permalink="https://example.test/vt",
        ),
    )

    captured: dict[str, object] = {}

    def _fake_analyze_with_ai(target, provider, vt_report=None):
        captured["vt_report"] = vt_report
        return AIReport(provider="test", model="test", findings=[])

    monkeypatch.setattr(pipeline_module, "analyze_with_ai", _fake_analyze_with_ai)

    report = run_scan(targets, provider=object(), vt_api_key="vt-key", enable_ai=True, enable_vt=True)
    assert report.scanned_targets == 1
    assert isinstance(captured.get("vt_report"), VTReport)
