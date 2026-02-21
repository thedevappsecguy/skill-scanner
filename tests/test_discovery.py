from __future__ import annotations

from pathlib import Path

from skill_scanner.discovery.finder import discover_targets
from skill_scanner.models.targets import Platform, Scope


def test_discover_from_custom_path(fixture_root: Path) -> None:
    targets = discover_targets(path=str(fixture_root / "clean_skill"), platform=Platform.ALL)
    assert targets
    assert any(target.kind.value == "skill" for target in targets)


def test_discover_missing_path_returns_empty(tmp_path: Path) -> None:
    targets = discover_targets(path=str(tmp_path / "missing"), platform=Platform.ALL, scopes={Scope.REPO})
    assert targets == []


def test_custom_path_ignores_json_and_toml_targets(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text("No frontmatter.\n", encoding="utf-8")
    (tmp_path / "mcp.json").write_text("{}", encoding="utf-8")
    (tmp_path / "settings.json").write_text("{}", encoding="utf-8")
    (tmp_path / "extensions.json").write_text("{}", encoding="utf-8")
    (tmp_path / "config.toml").write_text("name = 'test'\n", encoding="utf-8")

    targets = discover_targets(path=str(tmp_path), platform=Platform.ALL)
    kinds = [target.kind.value for target in targets]

    assert kinds == ["skill"]


def test_custom_root_skill_limits_collected_files(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "junk.py").write_text("print('x')\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("unrelated\n", encoding="utf-8")
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text("No frontmatter.\n", encoding="utf-8")

    targets = discover_targets(path=str(skill_path), platform=Platform.ALL)
    assert len(targets) == 1
    assert [file.relative_path for file in targets[0].files] == ["SKILL.md"]


def test_custom_root_skill_includes_referenced_script(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    script_path = scripts_dir / "install.sh"
    script_path.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    skill_path = tmp_path / "SKILL.md"
    skill_path.write_text("Run `scripts/install.sh`.\n", encoding="utf-8")

    targets = discover_targets(path=str(skill_path), platform=Platform.ALL)
    assert len(targets) == 1
    rel_paths = {file.relative_path for file in targets[0].files}
    assert rel_paths == {"SKILL.md", "scripts/install.sh"}
