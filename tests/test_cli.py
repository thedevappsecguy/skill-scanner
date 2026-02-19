from __future__ import annotations

from typer.testing import CliRunner

import skill_scanner.cli as cli_module
from skill_scanner.cli import _apply_min_severity_filter, app
from skill_scanner.config import Settings
from skill_scanner.models.findings import Category, Finding, Severity
from skill_scanner.models.reports import ScanReport, SkillReport
from skill_scanner.models.targets import Platform, ScanTarget, Scope, TargetKind

runner = CliRunner()


def test_providers_command() -> None:
    result = runner.invoke(app, ["providers"])
    assert result.exit_code == 0
    assert "openai" in result.stdout


def test_doctor_command() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "provider=" in result.stdout
    assert "OPENAI_API_KEY" in result.stdout
    assert "VT_API_KEY" in result.stdout


def test_scan_summary_format_output(monkeypatch, fixture_root) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_settings",
        lambda **_: Settings(
            provider="openai",
            model="gpt-5.2",
            openai_api_key="openai-key",
            vt_api_key=None,
        ),
    )
    monkeypatch.setattr(cli_module, "create_provider", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        cli_module,
        "run_scan",
        lambda targets, **_kwargs: ScanReport(
            scanned_targets=len(targets),
            reports=[],
            summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0},
        ),
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "--path",
            str(fixture_root / "clean_skill"),
            "--no-vt",
            "--format",
            "summary",
        ],
    )
    assert result.exit_code == 0
    assert "Skill Scanner Summary" in result.stdout
    assert "Scanned targets:" in result.stdout


def test_min_severity_filter_recomputes_score_and_summary() -> None:
    target = ScanTarget(
        id="target-1",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path="/tmp/SKILL.md",
        root_dir="/tmp",
        files=[],
    )
    report = ScanReport(
        scanned_targets=1,
        reports=[
            SkillReport(
                target=target,
                deterministic_findings=[
                    Finding(
                        source="deterministic",
                        category=Category.CONFIGURATION_RISK,
                        severity=Severity.LOW,
                        title="Low risk",
                        description="Low severity finding",
                    )
                ],
            )
        ],
        summary={"critical": 0, "high": 0, "medium": 0, "low": 1, "clean": 0},
    )

    _apply_min_severity_filter(report, Severity.HIGH)

    assert report.reports[0].deterministic_findings == []
    assert report.reports[0].ai_findings == []
    assert report.reports[0].score == 0.0
    assert report.reports[0].risk_level.value == "clean"
    assert report.summary == {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 1}


def test_scan_with_only_vt_key_disables_ai_with_hint(monkeypatch, tmp_path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: test-skill\ndescription: demo\n---\nbody\n", encoding="utf-8")

    monkeypatch.setattr(
        cli_module,
        "load_settings",
        lambda **_: Settings(provider="openai", model="gpt-5.2", openai_api_key=None, vt_api_key="vt-key"),
    )

    def _unexpected_provider(*_args, **_kwargs):
        raise AssertionError("create_provider should not be called when OPENAI_API_KEY is missing")

    monkeypatch.setattr(cli_module, "create_provider", _unexpected_provider)

    captured: dict[str, object] = {}

    def _fake_run_scan(targets, **kwargs):
        captured.update(kwargs)
        return ScanReport(
            scanned_targets=len(targets),
            reports=[],
            summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0},
        )

    monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

    result = runner.invoke(app, ["scan", "--path", str(skill), "--format", "summary"])
    assert result.exit_code == 0
    assert "OPENAI_API_KEY is missing" in result.stdout
    assert captured["enable_ai"] is False
    assert captured["enable_vt"] is True


def test_scan_with_only_openai_key_disables_vt_with_hint(monkeypatch, tmp_path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: test-skill\ndescription: demo\n---\nbody\n", encoding="utf-8")

    monkeypatch.setattr(
        cli_module,
        "load_settings",
        lambda **_: Settings(provider="openai", model="gpt-5.2", openai_api_key="openai-key", vt_api_key=None),
    )

    monkeypatch.setattr(cli_module, "create_provider", lambda *_args, **_kwargs: object())

    captured: dict[str, object] = {}

    def _fake_run_scan(targets, **kwargs):
        captured.update(kwargs)
        return ScanReport(
            scanned_targets=len(targets),
            reports=[],
            summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0},
        )

    monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

    result = runner.invoke(app, ["scan", "--path", str(skill), "--format", "summary"])
    assert result.exit_code == 0
    assert "VT_API_KEY is missing" in result.stdout
    assert captured["enable_ai"] is True
    assert captured["enable_vt"] is False


def test_scan_fails_when_no_analyzers_enabled_for_network(monkeypatch, tmp_path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: test-skill\ndescription: demo\n---\nbody\n", encoding="utf-8")

    monkeypatch.setattr(
        cli_module,
        "load_settings",
        lambda **_: Settings(provider="openai", model="gpt-5.2", openai_api_key=None, vt_api_key=None),
    )

    def _unexpected_run_scan(*_args, **_kwargs):
        raise AssertionError("run_scan should not be called when no analyzers are enabled in network mode")

    monkeypatch.setattr(cli_module, "run_scan", _unexpected_run_scan)

    result = runner.invoke(app, ["scan", "--path", str(skill), "--format", "summary"])
    assert result.exit_code == 2
    assert "No analyzers enabled for scan" in result.stdout
