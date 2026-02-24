from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from skill_scanner.discovery.patterns import (
    EXTENSION_PATTERNS,
    REPO_PATTERNS,
    SYSTEM_PATTERNS,
    USER_PATTERNS,
    DiscoveryPattern,
    matches_platform,
)
from skill_scanner.models.targets import Platform, ScanTarget, Scope, SkillFile, TargetKind

logger = logging.getLogger(__name__)

SUPPORTED_SUFFIXES = {
    "SKILL.md",
    "AGENTS.md",
    ".agent.md",
}

IGNORED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".cache",
    "dist",
    "build",
    ".tox",
}

IGNORED_FILE_NAMES = {
    ".DS_Store",
    ".env",
    ".env.local",
    ".env.development",
    ".env.test",
    ".env.production",
}

IGNORED_FILE_SUFFIXES = {
    ".pyc",
    ".pyo",
}

SKILL_REFERENCE_LINK_RE = re.compile(r"\[[^\]]+]\(([^)]+)\)")
SKILL_REFERENCE_CODE_RE = re.compile(r"`([^`\n]+)`")
REPO_ROOT_MARKERS = {
    ".git",
    "pyproject.toml",
    "package.json",
    "go.mod",
    "Cargo.toml",
}
SKILL_COMPANION_DIRS = ("scripts", "assets", "references", "templates", "examples")
CUSTOM_PATH_PATTERNS: tuple[DiscoveryPattern, ...] = (
    DiscoveryPattern(Platform.GENERIC, Scope.REPO, "SKILL.md", TargetKind.SKILL),
    *REPO_PATTERNS,
    *USER_PATTERNS,
    *EXTENSION_PATTERNS,
)


@dataclass
class DiscoveryDiagnostics:
    warnings: list[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        logger.info("discovery warning: %s", message)


def _repo_root(start: Path) -> Path | None:
    try:
        current = start.resolve()
    except OSError:
        return None
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def _warn_oserror(diagnostics: DiscoveryDiagnostics, context: str, error: OSError) -> None:
    diagnostics.warn(f"{context}: {error.__class__.__name__}: {error}")


def _iter_matches(root: Path, pattern: str, diagnostics: DiscoveryDiagnostics) -> list[Path]:
    base = Path("/") if pattern.startswith("/") else root
    glob_pattern = pattern[1:] if pattern.startswith("/") else pattern
    matches: list[Path] = []
    if pattern.startswith("/"):
        context = f"failed scanning absolute pattern '{pattern}'"
    else:
        context = f"failed scanning pattern '{pattern}' under '{root}'"

    try:
        iterator = base.glob(glob_pattern)
    except OSError as error:
        _warn_oserror(diagnostics, context, error)
        return matches

    while True:
        try:
            path = next(iterator)
        except StopIteration:
            break
        except OSError as error:
            _warn_oserror(diagnostics, context, error)
            break
        try:
            if path.exists():
                matches.append(path)
        except OSError as error:
            _warn_oserror(diagnostics, f"failed checking discovered path '{path}'", error)
    return matches


def _is_ignored_file(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    if any(part in IGNORED_DIR_NAMES for part in rel.parts[:-1]):
        return True
    name = rel.name
    if name in IGNORED_FILE_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in IGNORED_FILE_SUFFIXES)


def _iter_files(root: Path, diagnostics: DiscoveryDiagnostics, *, apply_ignores: bool = True) -> list[Path]:
    files: list[Path] = []
    try:
        iterator = root.rglob("*")
    except OSError as error:
        _warn_oserror(diagnostics, f"failed walking files under '{root}'", error)
        return files

    while True:
        try:
            file_path = next(iterator)
        except StopIteration:
            break
        except OSError as error:
            _warn_oserror(diagnostics, f"failed walking files under '{root}'", error)
            break
        try:
            if not file_path.is_file():
                continue
        except OSError as error:
            _warn_oserror(diagnostics, f"failed reading file metadata '{file_path}'", error)
            continue
        if apply_ignores and _is_ignored_file(file_path, root):
            continue
        files.append(file_path)

    return sorted(files, key=lambda item: str(item))


def _to_skill_file(path: Path, root: Path, diagnostics: DiscoveryDiagnostics) -> SkillFile | None:
    try:
        resolved = path.resolve()
    except OSError as error:
        _warn_oserror(diagnostics, f"failed resolving file '{path}'", error)
        return None

    try:
        relative = str(resolved.relative_to(root))
    except ValueError:
        relative = resolved.name

    try:
        size = resolved.stat().st_size
    except OSError as error:
        _warn_oserror(diagnostics, f"failed reading file size '{resolved}'", error)
        return None

    return SkillFile(
        path=str(resolved),
        relative_path=relative,
        size=size,
    )


def _looks_like_repo_root(path: Path) -> bool:
    return any((path / marker).exists() for marker in REPO_ROOT_MARKERS)


def _extract_local_references(skill_md: Path, root: Path, diagnostics: DiscoveryDiagnostics) -> set[Path]:
    try:
        text = skill_md.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return set()

    candidates: set[str] = set()
    candidates.update(match.strip() for match in SKILL_REFERENCE_LINK_RE.findall(text))
    candidates.update(match.strip() for match in SKILL_REFERENCE_CODE_RE.findall(text))

    try:
        root_resolved = root.resolve()
    except OSError as error:
        _warn_oserror(diagnostics, f"failed resolving skill root '{root}'", error)
        return set()

    references: set[Path] = set()
    for candidate in candidates:
        value = candidate.strip().strip("<>").strip("'").strip('"')
        if not value or value.startswith("#"):
            continue
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value):
            continue
        value = value.split("#", 1)[0].split("?", 1)[0]
        try:
            resolved = (root / value).resolve()
        except OSError as error:
            _warn_oserror(diagnostics, f"failed resolving local reference '{value}' in '{skill_md}'", error)
            continue
        if not resolved.exists():
            continue
        try:
            resolved.relative_to(root_resolved)
        except ValueError:
            continue
        references.add(resolved)
    return references


def _collect_skill_files(skill_md: Path, diagnostics: DiscoveryDiagnostics) -> list[SkillFile]:
    root = skill_md.parent
    try:
        root_resolved = root.resolve()
    except OSError as error:
        _warn_oserror(diagnostics, f"failed resolving skill root '{root}'", error)
        return []

    if not _looks_like_repo_root(root_resolved):
        files: list[SkillFile] = []
        for file_path in _iter_files(root_resolved, diagnostics):
            skill_file = _to_skill_file(file_path, root_resolved, diagnostics)
            if skill_file is not None:
                files.append(skill_file)
        return files

    selected: set[Path] = set()
    try:
        selected.add(skill_md.resolve())
    except OSError as error:
        _warn_oserror(diagnostics, f"failed resolving skill file '{skill_md}'", error)
        return []

    for dirname in SKILL_COMPANION_DIRS:
        candidate_dir = root_resolved / dirname
        if candidate_dir.exists() and candidate_dir.is_dir():
            selected.update(_iter_files(candidate_dir, diagnostics))

    for reference in _extract_local_references(skill_md, root_resolved, diagnostics):
        if reference.is_file() and not _is_ignored_file(reference, root_resolved):
            selected.add(reference)
            continue
        if reference.is_dir():
            selected.update(_iter_files(reference, diagnostics))

    selected_files: list[SkillFile] = []
    for file_path in sorted(selected, key=lambda item: str(item)):
        skill_file = _to_skill_file(file_path, root_resolved, diagnostics)
        if skill_file is not None:
            selected_files.append(skill_file)
    return selected_files


def _single_file(file_path: Path, root: Path, diagnostics: DiscoveryDiagnostics) -> list[SkillFile]:
    try:
        resolved_file = file_path.resolve()
    except OSError as error:
        _warn_oserror(diagnostics, f"failed resolving file '{file_path}'", error)
        return []

    try:
        resolved_root = root.resolve()
    except OSError:
        resolved_root = root

    try:
        relative = str(resolved_file.relative_to(resolved_root))
    except ValueError:
        relative = resolved_file.name

    try:
        size = resolved_file.stat().st_size
    except OSError as error:
        _warn_oserror(diagnostics, f"failed reading file size '{resolved_file}'", error)
        return []

    return [
        SkillFile(
            path=str(resolved_file),
            relative_path=relative,
            size=size,
        )
    ]


def _target_id(path: Path, kind: TargetKind, platform: Platform, scope: Scope) -> str:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    value = f"{resolved}:{kind.value}:{platform.value}:{scope.value}"
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]


def _kind_from_file(path: Path) -> TargetKind | None:
    name = path.name
    if name == "SKILL.md":
        return TargetKind.SKILL
    if name.endswith(".instructions.md") or name in {"AGENTS.md", "CLAUDE.md", "copilot-instructions.md"}:
        return TargetKind.INSTRUCTION
    if name.endswith(".prompt.md"):
        return TargetKind.PROMPT
    if name.endswith(".agent.md"):
        return TargetKind.AGENT
    if name.endswith(".mdc") or name == ".cursorrules":
        return TargetKind.RULE
    if name.endswith(".md"):
        return TargetKind.COMMAND
    return None


def _kind_from_custom_path_file(path: Path) -> TargetKind | None:
    name = path.name
    if name == "SKILL.md":
        return TargetKind.SKILL
    if name.endswith(".instructions.md") or name in {
        "AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        "copilot-instructions.md",
    }:
        return TargetKind.INSTRUCTION
    if name.endswith(".agent.md"):
        return TargetKind.AGENT
    if name.endswith(".prompt.md"):
        return TargetKind.PROMPT
    if path.suffix.lower() == ".md" and path.parent.name == "agents" and (
        ".claude" in path.parts or ".opencode" in path.parts or ".gemini" in path.parts
    ):
        return TargetKind.AGENT
    if path.suffix.lower() == ".md" and path.parent.name == "commands" and ".claude" in path.parts:
        return TargetKind.COMMAND
    if name.endswith(".mdc") or name == ".cursorrules":
        return TargetKind.RULE
    return None


def _custom_path_globs(pattern: str) -> tuple[str, ...]:
    if pattern.startswith("/"):
        return ()
    if pattern.startswith("**/"):
        return (pattern,)
    return (pattern, f"**/{pattern}")


def _targets_from_custom_directory(
    root: Path,
    platform: Platform,
    scope: Scope,
    diagnostics: DiscoveryDiagnostics,
) -> list[ScanTarget]:
    discovered: dict[str, ScanTarget] = {}
    for pattern in CUSTOM_PATH_PATTERNS:
        if not matches_platform(platform, pattern.platform, pattern.explicit_platform_only):
            continue
        for glob_pattern in _custom_path_globs(pattern.glob):
            for match in _iter_matches(root, glob_pattern, diagnostics):
                try:
                    if not match.is_file():
                        continue
                except OSError as error:
                    _warn_oserror(diagnostics, f"failed reading file metadata '{match}'", error)
                    continue
                if _is_ignored_file(match, root):
                    continue

                try:
                    entry = match.resolve()
                except OSError as error:
                    _warn_oserror(diagnostics, f"failed resolving discovered match '{match}'", error)
                    continue

                if pattern.kind == TargetKind.EXTENSION:
                    for extension_target in _extension_targets(entry, diagnostics):
                        target = ScanTarget(
                            id=_target_id(
                                Path(extension_target.entry_path),
                                extension_target.kind,
                                extension_target.platform,
                                scope,
                            ),
                            kind=extension_target.kind,
                            platform=extension_target.platform,
                            scope=scope,
                            entry_path=extension_target.entry_path,
                            root_dir=extension_target.root_dir,
                            files=extension_target.files,
                        )
                        discovered[target.entry_path] = target
                    continue

                files = (
                    _collect_skill_files(entry, diagnostics)
                    if pattern.kind == TargetKind.SKILL
                    else _single_file(entry, root, diagnostics)
                )
                target = ScanTarget(
                    id=_target_id(entry, pattern.kind, pattern.platform, scope),
                    kind=pattern.kind,
                    platform=pattern.platform,
                    scope=scope,
                    entry_path=str(entry),
                    root_dir=str(entry.parent),
                    files=files,
                )
                discovered[str(entry)] = target

    return sorted(discovered.values(), key=lambda item: item.entry_path)


def _targets_from_custom_path(
    path: Path,
    platform: Platform,
    scope: Scope,
    diagnostics: DiscoveryDiagnostics,
) -> list[ScanTarget]:
    if path.is_file():
        kind = _kind_from_custom_path_file(path)
        if kind is None:
            return []
        try:
            resolved_path = path.resolve()
        except OSError as error:
            _warn_oserror(diagnostics, f"failed resolving custom-path file '{path}'", error)
            return []
        root = path.parent
        files = (
            _collect_skill_files(path, diagnostics)
            if kind == TargetKind.SKILL
            else _single_file(path, root, diagnostics)
        )
        return [
            ScanTarget(
                id=_target_id(path, kind, platform, scope),
                kind=kind,
                platform=platform,
                scope=scope,
                entry_path=str(resolved_path),
                root_dir=str(resolved_path.parent),
                files=files,
            )
        ]

    if not path.is_dir():
        return []

    return _targets_from_custom_directory(path, platform, scope, diagnostics)


def _extension_targets(package_json: Path, diagnostics: DiscoveryDiagnostics) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    try:
        payload = json.loads(package_json.read_text(encoding="utf-8"))
    except Exception:
        return targets
    contributed = payload.get("contributes", {}).get("chatSkills", [])
    if not isinstance(contributed, list):
        return targets
    for skill in contributed:
        if not isinstance(skill, dict):
            continue
        raw_path = skill.get("path")
        if not isinstance(raw_path, str):
            continue
        try:
            skill_md = (package_json.parent / raw_path / "SKILL.md").resolve()
        except OSError as error:
            _warn_oserror(
                diagnostics,
                f"failed resolving extension skill path '{raw_path}' from '{package_json}'",
                error,
            )
            continue
        if not skill_md.exists():
            continue
        targets.append(
            ScanTarget(
                id=_target_id(skill_md, TargetKind.SKILL, Platform.VSCODE, Scope.EXTENSION),
                kind=TargetKind.SKILL,
                platform=Platform.VSCODE,
                scope=Scope.EXTENSION,
                entry_path=str(skill_md),
                root_dir=str(skill_md.parent),
                files=_collect_skill_files(skill_md, diagnostics),
            )
        )
    return targets


def discover_targets_with_diagnostics(
    path: str | None = None,
    platform: Platform = Platform.ALL,
    scopes: set[Scope] | None = None,
) -> tuple[list[ScanTarget], list[str]]:
    diagnostics = DiscoveryDiagnostics()
    selected_scopes = scopes or {Scope.REPO, Scope.USER, Scope.SYSTEM, Scope.EXTENSION}
    cwd = Path.cwd()
    repo_root = _repo_root(cwd)
    repo_scope_enabled = Scope.REPO in selected_scopes and repo_root is not None

    if Scope.REPO in selected_scopes and repo_root is None:
        diagnostics.warn(
            f"Skipping repo scope because '{cwd}' is not inside a git repository. "
            "Use --path or run from a repository root."
        )

    if path:
        try:
            custom_path = Path(path).expanduser().resolve()
        except OSError as error:
            _warn_oserror(diagnostics, f"failed resolving custom path '{path}'", error)
            return ([], diagnostics.warnings)
        if not custom_path.exists():
            return ([], diagnostics.warnings)
        targets = _targets_from_custom_path(custom_path, platform, Scope.REPO, diagnostics)
        return (targets, diagnostics.warnings)

    discovered: dict[str, ScanTarget] = {}

    if repo_scope_enabled and repo_root is not None:
        for pattern in REPO_PATTERNS:
            if not matches_platform(platform, pattern.platform, pattern.explicit_platform_only):
                continue
            for match in _iter_matches(repo_root, pattern.glob, diagnostics):
                try:
                    entry = match.resolve()
                except OSError as error:
                    _warn_oserror(diagnostics, f"failed resolving discovered match '{match}'", error)
                    continue
                files = (
                    _collect_skill_files(entry, diagnostics)
                    if pattern.kind == TargetKind.SKILL
                    else _single_file(entry, repo_root, diagnostics)
                )
                target = ScanTarget(
                    id=_target_id(entry, pattern.kind, pattern.platform, Scope.REPO),
                    kind=pattern.kind,
                    platform=pattern.platform,
                    scope=Scope.REPO,
                    entry_path=str(entry),
                    root_dir=str(entry.parent),
                    files=files,
                )
                discovered[str(entry)] = target

    home = Path.home()
    for pattern in USER_PATTERNS:
        if Scope.USER not in selected_scopes or not matches_platform(platform, pattern.platform, pattern.explicit_platform_only):
            continue
        for match in _iter_matches(home, pattern.glob, diagnostics):
            try:
                entry = match.resolve()
            except OSError as error:
                _warn_oserror(diagnostics, f"failed resolving discovered match '{match}'", error)
                continue
            files = (
                _collect_skill_files(entry, diagnostics)
                if pattern.kind == TargetKind.SKILL
                else _single_file(entry, home, diagnostics)
            )
            target = ScanTarget(
                id=_target_id(entry, pattern.kind, pattern.platform, Scope.USER),
                kind=pattern.kind,
                platform=pattern.platform,
                scope=Scope.USER,
                entry_path=str(entry),
                root_dir=str(entry.parent),
                files=files,
            )
            discovered[str(entry)] = target

    for pattern in SYSTEM_PATTERNS:
        if Scope.SYSTEM not in selected_scopes or not matches_platform(platform, pattern.platform, pattern.explicit_platform_only):
            continue
        for match in _iter_matches(Path("/"), pattern.glob, diagnostics):
            try:
                entry = match.resolve()
            except OSError as error:
                _warn_oserror(diagnostics, f"failed resolving discovered match '{match}'", error)
                continue
            target = ScanTarget(
                id=_target_id(entry, pattern.kind, pattern.platform, Scope.SYSTEM),
                kind=pattern.kind,
                platform=pattern.platform,
                scope=Scope.SYSTEM,
                entry_path=str(entry),
                root_dir=str(entry.parent),
                files=_collect_skill_files(entry, diagnostics),
            )
            discovered[str(entry)] = target

    for pattern in EXTENSION_PATTERNS:
        if Scope.EXTENSION not in selected_scopes or not matches_platform(platform, pattern.platform, pattern.explicit_platform_only):
            continue
        for match in _iter_matches(home, pattern.glob, diagnostics):
            try:
                match_resolved = match.resolve()
            except OSError as error:
                _warn_oserror(diagnostics, f"failed resolving extension manifest '{match}'", error)
                continue
            for target in _extension_targets(match_resolved, diagnostics):
                discovered[target.entry_path] = target

    return (sorted(discovered.values(), key=lambda item: item.entry_path), diagnostics.warnings)


def discover_targets(
    path: str | None = None,
    platform: Platform = Platform.ALL,
    scopes: set[Scope] | None = None,
) -> list[ScanTarget]:
    targets, _warnings = discover_targets_with_diagnostics(path=path, platform=platform, scopes=scopes)
    return targets
