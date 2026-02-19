from __future__ import annotations

from pathlib import Path

from skill_scanner.analyzers.ai_analyzer import analyze_with_ai, build_payload
from skill_scanner.models.reports import AIReport, VTReport
from skill_scanner.models.targets import Platform, ScanTarget, Scope, SkillFile, TargetKind
from skill_scanner.providers.base import LLMProvider


def test_build_payload_skips_large_file_and_keeps_scanning(tmp_path: Path) -> None:
    large_file = tmp_path / "large.md"
    small_file = tmp_path / "small.md"
    large_file.write_text("x" * 5_000, encoding="utf-8")
    small_file.write_text("safe content", encoding="utf-8")

    target = ScanTarget(
        id="target-1",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path=str(tmp_path / "SKILL.md"),
        root_dir=str(tmp_path),
        files=[
            SkillFile(path=str(large_file), relative_path="large.md", size=large_file.stat().st_size),
            SkillFile(path=str(small_file), relative_path="small.md", size=small_file.stat().st_size),
        ],
    )

    payload = build_payload(target, max_chars=500)
    assert "small.md" in payload
    assert "safe content" in payload


class _RecordingProvider(LLMProvider):
    name = "test"

    def __init__(self) -> None:
        super().__init__(api_key="test-key", model="test-model")
        self.last_payload = ""

    def analyze(self, target: ScanTarget, payload: str) -> AIReport:
        self.last_payload = payload
        return AIReport(provider=self.name, model=self.model, findings=[])


def test_analyze_with_ai_includes_vt_context(tmp_path: Path) -> None:
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("content", encoding="utf-8")
    target = ScanTarget(
        id="target-1",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path=str(skill_file),
        root_dir=str(tmp_path),
        files=[SkillFile(path=str(skill_file), relative_path="SKILL.md", size=skill_file.stat().st_size)],
    )
    provider = _RecordingProvider()
    vt_report = VTReport(
        sha256="abc",
        malicious=1,
        suspicious=0,
        harmless=0,
        undetected=5,
        permalink="https://example.test/vt",
    )

    analyze_with_ai(target, provider, vt_report=vt_report)
    assert "## VIRUSTOTAL_CONTEXT" in provider.last_payload
    assert "malicious: 1" in provider.last_payload
