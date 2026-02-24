from __future__ import annotations

from pathlib import Path

import skill_scanner.discovery.finder as finder_module
from skill_scanner.discovery.finder import discover_targets, discover_targets_with_diagnostics
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


def _write_skill(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\nname: test\ndescription: demo\n---\nbody\n", encoding="utf-8")


def test_repo_patterns_discover_windsurf_gemini_cline_opencode(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".git").mkdir()
    _write_skill(tmp_path / ".windsurf/skills/a/SKILL.md")
    _write_skill(tmp_path / ".gemini/skills/b/SKILL.md")
    _write_skill(tmp_path / ".cline/skills/c/SKILL.md")
    _write_skill(tmp_path / ".opencode/skills/d/SKILL.md")

    monkeypatch.chdir(tmp_path)
    targets = discover_targets(platform=Platform.ALL, scopes={Scope.REPO})

    platforms = {target.platform for target in targets if target.kind.value == "skill"}
    assert platforms.issuperset(
        {Platform.WINDSURF, Platform.GEMINI, Platform.CLINE, Platform.OPENCODE}
    )


def test_user_patterns_discover_windsurf_gemini_cline_opencode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    _write_skill(tmp_path / ".codeium/windsurf/skills/a/SKILL.md")
    _write_skill(tmp_path / ".gemini/skills/b/SKILL.md")
    _write_skill(tmp_path / ".cline/skills/c/SKILL.md")
    _write_skill(tmp_path / ".clinerules/skills/c/SKILL.md")
    _write_skill(tmp_path / ".config/opencode/skills/d/SKILL.md")

    targets = discover_targets(platform=Platform.ALL, scopes={Scope.USER})

    platforms = {target.platform for target in targets if target.kind.value == "skill"}
    assert platforms.issuperset(
        {Platform.WINDSURF, Platform.GEMINI, Platform.CLINE, Platform.OPENCODE}
    )


def test_platform_filter_returns_only_windsurf(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".git").mkdir()
    _write_skill(tmp_path / ".windsurf/skills/a/SKILL.md")
    _write_skill(tmp_path / ".gemini/skills/b/SKILL.md")

    monkeypatch.chdir(tmp_path)
    targets = discover_targets(platform=Platform.WINDSURF, scopes={Scope.REPO})

    assert targets
    assert all(target.platform == Platform.WINDSURF for target in targets)


def test_cline_clinerules_alias_is_discovered_in_repo_scope(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".git").mkdir()
    _write_skill(tmp_path / ".clinerules/skills/alias/SKILL.md")

    monkeypatch.chdir(tmp_path)
    targets = discover_targets(platform=Platform.CLINE, scopes={Scope.REPO})

    assert targets
    assert any("/.clinerules/skills/alias/SKILL.md" in target.entry_path for target in targets)


def test_shared_paths_are_platform_specific(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".git").mkdir()
    _write_skill(tmp_path / ".agents/skills/shared/SKILL.md")
    _write_skill(tmp_path / ".claude/skills/legacy/SKILL.md")

    monkeypatch.chdir(tmp_path)

    all_targets = discover_targets(platform=Platform.ALL, scopes={Scope.REPO})
    gemini_targets = discover_targets(platform=Platform.GEMINI, scopes={Scope.REPO})
    opencode_targets = discover_targets(platform=Platform.OPENCODE, scopes={Scope.REPO})

    all_agents_platforms = {
        target.platform for target in all_targets if "/.agents/skills/shared/SKILL.md" in target.entry_path
    }
    gemini_agents_platforms = {
        target.platform for target in gemini_targets if "/.agents/skills/shared/SKILL.md" in target.entry_path
    }
    opencode_agents_platforms = {
        target.platform for target in opencode_targets if "/.agents/skills/shared/SKILL.md" in target.entry_path
    }
    opencode_claude_platforms = {
        target.platform for target in opencode_targets if "/.claude/skills/legacy/SKILL.md" in target.entry_path
    }

    assert all_agents_platforms == {Platform.CODEX}
    assert gemini_agents_platforms == {Platform.GEMINI}
    assert opencode_agents_platforms == {Platform.OPENCODE}
    assert opencode_claude_platforms == {Platform.OPENCODE}


def test_discover_handles_repo_glob_errors_without_crashing(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".git").mkdir()
    monkeypatch.chdir(tmp_path)

    original_glob = Path.glob

    def _broken_glob(self: Path, pattern: str):
        if str(self) == str(tmp_path):
            raise InterruptedError("scandir interrupted")
        return original_glob(self, pattern)

    monkeypatch.setattr(Path, "glob", _broken_glob)

    targets, warnings = discover_targets_with_diagnostics(platform=Platform.ALL, scopes={Scope.REPO})
    assert targets == []
    assert any("InterruptedError" in warning for warning in warnings)


def test_custom_path_handles_rglob_errors_without_crashing(tmp_path: Path, monkeypatch) -> None:
    original_rglob = Path.rglob

    def _broken_rglob(self: Path, pattern: str):
        if str(self) == str(tmp_path):
            raise PermissionError("access denied")
        return original_rglob(self, pattern)

    monkeypatch.setattr(Path, "rglob", _broken_rglob)

    targets, warnings = discover_targets_with_diagnostics(path=str(tmp_path), platform=Platform.ALL)
    assert targets == []
    assert any("PermissionError" in warning for warning in warnings)


def test_default_discovery_skips_repo_scope_outside_git_repo(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    _write_skill(home / ".codex/skills/demo/SKILL.md")

    work_dir = tmp_path / "work"
    work_dir.mkdir()
    monkeypatch.chdir(work_dir)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(finder_module, "SYSTEM_PATTERNS", ())
    monkeypatch.setattr(finder_module, "EXTENSION_PATTERNS", ())

    targets, warnings = discover_targets_with_diagnostics(platform=Platform.ALL)

    assert any(target.scope == Scope.USER for target in targets)
    assert all(target.scope != Scope.REPO for target in targets)
    assert any("Skipping repo scope" in warning for warning in warnings)


def test_explicit_repo_scope_outside_repo_returns_warning(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    targets, warnings = discover_targets_with_diagnostics(platform=Platform.ALL, scopes={Scope.REPO})

    assert targets == []
    assert any("Skipping repo scope" in warning for warning in warnings)


def test_continue_and_amazonq_paths_are_not_discovered(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / ".git").mkdir()
    _write_skill(tmp_path / ".continue/skills/a/SKILL.md")
    _write_skill(tmp_path / ".amazonq/skills/b/SKILL.md")

    monkeypatch.chdir(tmp_path)
    targets = discover_targets(platform=Platform.ALL, scopes={Scope.REPO})

    assert targets == []
