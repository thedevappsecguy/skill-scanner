from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from skill_scanner.discovery.patterns import (
    EXTENSION_PATTERNS,
    REPO_PATTERNS,
    SYSTEM_PATTERNS,
    USER_PATTERNS,
    matches_platform,
)
from skill_scanner.models.targets import Platform, ScanTarget, Scope, SkillFile, TargetKind

SUPPORTED_SUFFIXES = {
    "SKILL.md",
    ".instructions.md",
    ".prompt.md",
    ".agent.md",
    ".mdc",
    ".md",
    ".json",
    ".toml",
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


def _repo_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return current


def _iter_matches(root: Path, pattern: str) -> list[Path]:
    if pattern.startswith("/"):
        return [p for p in Path("/").glob(pattern[1:]) if p.exists()]
    return [p for p in root.glob(pattern) if p.exists()]


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


def _iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for file_path in sorted(root.rglob("*")):
        if not file_path.is_file():
            continue
        if _is_ignored_file(file_path, root):
            continue
        files.append(file_path)
    return files


def _to_skill_file(path: Path, root: Path) -> SkillFile:
    return SkillFile(
        path=str(path.resolve()),
        relative_path=str(path.relative_to(root)),
        size=path.stat().st_size,
    )


def _looks_like_repo_root(path: Path) -> bool:
    return any((path / marker).exists() for marker in REPO_ROOT_MARKERS)


def _extract_local_references(skill_md: Path, root: Path) -> set[Path]:
    try:
        text = skill_md.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return set()

    candidates: set[str] = set()
    candidates.update(match.strip() for match in SKILL_REFERENCE_LINK_RE.findall(text))
    candidates.update(match.strip() for match in SKILL_REFERENCE_CODE_RE.findall(text))

    references: set[Path] = set()
    for candidate in candidates:
        value = candidate.strip().strip("<>").strip("'").strip('"')
        if not value or value.startswith("#"):
            continue
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value):
            continue
        value = value.split("#", 1)[0].split("?", 1)[0]
        resolved = (root / value).resolve()
        if not resolved.exists():
            continue
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            continue
        references.add(resolved)
    return references


def _collect_skill_files(skill_md: Path) -> list[SkillFile]:
    root = skill_md.parent
    root_resolved = root.resolve()

    if not _looks_like_repo_root(root_resolved):
        return [_to_skill_file(file_path, root_resolved) for file_path in _iter_files(root_resolved)]

    selected: set[Path] = {skill_md.resolve()}

    for dirname in SKILL_COMPANION_DIRS:
        candidate_dir = root_resolved / dirname
        if candidate_dir.exists() and candidate_dir.is_dir():
            selected.update(_iter_files(candidate_dir))

    for reference in _extract_local_references(skill_md, root_resolved):
        if reference.is_file() and not _is_ignored_file(reference, root_resolved):
            selected.add(reference)
            continue
        if reference.is_dir():
            selected.update(_iter_files(reference))

    return [_to_skill_file(file_path, root_resolved) for file_path in sorted(selected)]


def _single_file(file_path: Path, root: Path) -> list[SkillFile]:
    try:
        relative = str(file_path.resolve().relative_to(root.resolve()))
    except ValueError:
        relative = file_path.name
    return [
        SkillFile(
            path=str(file_path.resolve()),
            relative_path=relative,
            size=file_path.stat().st_size,
        )
    ]


def _target_id(path: Path, kind: TargetKind, platform: Platform, scope: Scope) -> str:
    value = f"{path.resolve()}:{kind.value}:{platform.value}:{scope.value}"
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
    if name == "mcp.json":
        return TargetKind.MCP
    if name in {"settings.json", "extensions.json", "config.toml"}:
        return TargetKind.CONFIG
    if name.endswith(".mdc") or name == ".cursorrules":
        return TargetKind.RULE
    if name.endswith(".md"):
        return TargetKind.COMMAND
    return None


def _targets_from_custom_path(path: Path, platform: Platform, scope: Scope) -> list[ScanTarget]:
    candidates: list[Path] = []
    if path.is_file():
        candidates = [path]
    elif path.is_dir():
        for file_path in path.rglob("*"):
            if not file_path.is_file():
                continue
            suffix = file_path.suffix.lower()
            if file_path.name in SUPPORTED_SUFFIXES or suffix in {".md", ".json", ".toml", ".mdc"}:
                candidates.append(file_path)
    targets: list[ScanTarget] = []
    seen: set[str] = set()
    for file_path in candidates:
        kind = _kind_from_file(file_path)
        if kind is None:
            continue
        resolved = str(file_path.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        files = _collect_skill_files(file_path) if kind == TargetKind.SKILL else _single_file(file_path, path)
        target = ScanTarget(
            id=_target_id(file_path, kind, platform, scope),
            kind=kind,
            platform=platform,
            scope=scope,
            entry_path=resolved,
            root_dir=str(file_path.parent.resolve()),
            files=files,
        )
        targets.append(target)
    return targets


def _extension_targets(package_json: Path) -> list[ScanTarget]:
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
        skill_md = (package_json.parent / raw_path / "SKILL.md").resolve()
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
                files=_collect_skill_files(skill_md),
            )
        )
    return targets


def discover_targets(
    path: str | None = None,
    platform: Platform = Platform.ALL,
    scopes: set[Scope] | None = None,
) -> list[ScanTarget]:
    selected_scopes = scopes or {Scope.REPO, Scope.USER, Scope.SYSTEM, Scope.EXTENSION}
    cwd = Path.cwd()
    repo_root = _repo_root(cwd)

    if path:
        custom_path = Path(path).expanduser().resolve()
        if not custom_path.exists():
            return []
        return _targets_from_custom_path(custom_path, platform, Scope.REPO)

    discovered: dict[str, ScanTarget] = {}

    for pattern in REPO_PATTERNS:
        if Scope.REPO not in selected_scopes or not matches_platform(platform, pattern.platform):
            continue
        for match in _iter_matches(repo_root, pattern.glob):
            entry = match.resolve()
            files = _collect_skill_files(entry) if pattern.kind == TargetKind.SKILL else _single_file(entry, repo_root)
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
        if Scope.USER not in selected_scopes or not matches_platform(platform, pattern.platform):
            continue
        for match in _iter_matches(home, pattern.glob):
            entry = match.resolve()
            files = _collect_skill_files(entry) if pattern.kind == TargetKind.SKILL else _single_file(entry, home)
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
        if Scope.SYSTEM not in selected_scopes or not matches_platform(platform, pattern.platform):
            continue
        for match in _iter_matches(Path("/"), pattern.glob):
            entry = match.resolve()
            target = ScanTarget(
                id=_target_id(entry, pattern.kind, pattern.platform, Scope.SYSTEM),
                kind=pattern.kind,
                platform=pattern.platform,
                scope=Scope.SYSTEM,
                entry_path=str(entry),
                root_dir=str(entry.parent),
                files=_collect_skill_files(entry),
            )
            discovered[str(entry)] = target

    for pattern in EXTENSION_PATTERNS:
        if Scope.EXTENSION not in selected_scopes or not matches_platform(platform, pattern.platform):
            continue
        for match in _iter_matches(home, pattern.glob):
            for target in _extension_targets(match.resolve()):
                discovered[target.entry_path] = target

    return sorted(discovered.values(), key=lambda item: item.entry_path)
