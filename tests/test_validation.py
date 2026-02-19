from __future__ import annotations

from pathlib import Path

from skill_scanner.models.targets import Platform, ScanTarget, Scope, SkillFile, TargetKind
from skill_scanner.validation.skill_spec import validate_skill_target
from skill_scanner.validation.static_rules import run_static_rules


def _target(path: Path) -> ScanTarget:
    root = path.parent
    return ScanTarget(
        id="x",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path=str(path),
        root_dir=str(root),
        files=[
            SkillFile(path=str(file), relative_path=str(file.relative_to(root)), size=file.stat().st_size)
            for file in root.rglob("*")
            if file.is_file()
        ],
    )


def test_skill_spec_validation_detects_mismatch(tmp_path: Path) -> None:
    skill_dir = tmp_path / "wrong-name"
    skill_dir.mkdir()
    skill = skill_dir / "SKILL.md"
    skill.write_text("---\nname: other-name\ndescription: demo\n---\nbody\n", encoding="utf-8")

    findings = validate_skill_target(_target(skill))
    assert any("mismatch" in finding.title.lower() for finding in findings)


def test_skill_spec_validation_handles_invalid_yaml(tmp_path: Path) -> None:
    skill_dir = tmp_path / "broken-skill"
    skill_dir.mkdir()
    skill = skill_dir / "SKILL.md"
    skill.write_text("---\nname: [unterminated\n---\nbody\n", encoding="utf-8")

    findings = validate_skill_target(_target(skill))
    assert any("frontmatter" in finding.title.lower() for finding in findings)


def test_static_rules_detect_exfiltration(fixture_root: Path) -> None:
    skill = fixture_root / "exfil_skill" / "SKILL.md"
    findings = run_static_rules(_target(skill))
    assert any(f.category.value == "data_exfiltration" for f in findings)
