from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

import skill_scanner.cli as cli_module
from skill_scanner.cli import _apply_min_severity_filter, app
from skill_scanner.config import Settings
from skill_scanner.models.findings import Category, Finding, Severity
from skill_scanner.models.reports import ScanReport, SkillReport
from skill_scanner.models.targets import Platform, ScanTarget, Scope, TargetKind

runner = CliRunner()


def _scan_target(entry_path: str) -> ScanTarget:
    return ScanTarget(
        id=entry_path,
        kind=TargetKind.SKILL,
        platform=Platform.CODEX,
        scope=Scope.REPO,
        entry_path=entry_path,
        root_dir=str(Path(entry_path).parent),
        files=[],
    )


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


def test_scan_list_targets_exits_before_analyzer_setup(monkeypatch, tmp_path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: test-skill\ndescription: demo\n---\nbody\n", encoding="utf-8")
    target = _scan_target(str(skill.resolve()))

    monkeypatch.setattr(cli_module, "discover_targets", lambda **_kwargs: [target])

    def _unexpected_load_settings(**_kwargs):
        raise AssertionError("load_settings should not run when --list-targets is used")

    monkeypatch.setattr(cli_module, "load_settings", _unexpected_load_settings)

    result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--list-targets"])
    assert result.exit_code == 0
    assert "Discovered 1 targets" in result.stdout
    assert "SKILL.md" in result.stdout


def test_scan_target_filters_discovered_entries(monkeypatch, tmp_path) -> None:
    first = tmp_path / "first" / "SKILL.md"
    second = tmp_path / "second" / "SKILL.md"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_text("---\nname: first\ndescription: demo\n---\nbody\n", encoding="utf-8")
    second.write_text("---\nname: second\ndescription: demo\n---\nbody\n", encoding="utf-8")

    discovered = [_scan_target(str(first.resolve())), _scan_target(str(second.resolve()))]
    monkeypatch.setattr(cli_module, "discover_targets", lambda **_kwargs: discovered)
    monkeypatch.setattr(
        cli_module,
        "load_settings",
        lambda **_: Settings(provider="openai", model="gpt-5.2", openai_api_key="openai-key", vt_api_key=None),
    )
    monkeypatch.setattr(cli_module, "create_provider", lambda *_args, **_kwargs: object())

    captured: dict[str, object] = {}

    def _fake_run_scan(targets, **kwargs):
        captured["targets"] = targets
        captured.update(kwargs)
        return ScanReport(
            scanned_targets=len(targets),
            reports=[],
            summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0},
        )

    monkeypatch.setattr(cli_module, "run_scan", _fake_run_scan)

    result = runner.invoke(
        app,
        [
            "scan",
            "--path",
            str(tmp_path),
            "--target",
            str(first.resolve()),
            "--no-vt",
            "--format",
            "summary",
        ],
    )
    assert result.exit_code == 0
    selected = captured["targets"]
    assert isinstance(selected, list)
    assert len(selected) == 1
    assert selected[0].entry_path == str(first.resolve())


def test_scan_target_filter_with_no_matches_exits(monkeypatch, tmp_path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text("---\nname: test\ndescription: demo\n---\nbody\n", encoding="utf-8")
    monkeypatch.setattr(cli_module, "discover_targets", lambda **_kwargs: [_scan_target(str(skill.resolve()))])

    def _unexpected_load_settings(**_kwargs):
        raise AssertionError("load_settings should not run when --target has no matches")

    monkeypatch.setattr(cli_module, "load_settings", _unexpected_load_settings)

    result = runner.invoke(
        app,
        ["scan", "--path", str(tmp_path), "--target", str(tmp_path / "missing" / "SKILL.md")],
    )
    assert result.exit_code == 2
    assert "No discovered targets matched --target values." in result.stdout
