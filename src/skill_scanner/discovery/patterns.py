from __future__ import annotations

from dataclasses import dataclass

from skill_scanner.models.targets import Platform, Scope, TargetKind


@dataclass(frozen=True)
class DiscoveryPattern:
    platform: Platform
    scope: Scope
    glob: str
    kind: TargetKind


REPO_PATTERNS: tuple[DiscoveryPattern, ...] = (
    DiscoveryPattern(Platform.CODEX, Scope.REPO, ".agents/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CODEX, Scope.REPO, "AGENTS.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, ".claude/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, "**/.claude/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, ".claude/commands/*.md", TargetKind.COMMAND),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, "CLAUDE.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, ".github/copilot-instructions.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, ".github/instructions/**/*.instructions.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, ".github/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, "AGENTS.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.CURSOR, Scope.REPO, ".cursor/rules/*.mdc", TargetKind.RULE),
    DiscoveryPattern(Platform.CURSOR, Scope.REPO, ".cursorrules", TargetKind.RULE),
    DiscoveryPattern(Platform.CURSOR, Scope.REPO, ".cursor/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.VSCODE, Scope.REPO, ".github/prompts/**/*.prompt.md", TargetKind.PROMPT),
    DiscoveryPattern(Platform.VSCODE, Scope.REPO, ".github/agents/**/*.agent.md", TargetKind.AGENT),
)

USER_PATTERNS: tuple[DiscoveryPattern, ...] = (
    DiscoveryPattern(Platform.CLAUDE, Scope.USER, ".claude/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLAUDE, Scope.USER, ".claude/CLAUDE.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.CODEX, Scope.USER, ".codex/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CODEX, Scope.USER, ".codex/skills/.system/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CODEX, Scope.USER, ".agents/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.COPILOT, Scope.USER, ".copilot/copilot-instructions.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.USER, ".copilot/skills/*/SKILL.md", TargetKind.SKILL),
)

SYSTEM_PATTERNS: tuple[DiscoveryPattern, ...] = (
    DiscoveryPattern(Platform.CODEX, Scope.SYSTEM, "/etc/codex/skills/*/SKILL.md", TargetKind.SKILL),
)

EXTENSION_PATTERNS: tuple[DiscoveryPattern, ...] = (
    DiscoveryPattern(Platform.VSCODE, Scope.EXTENSION, ".vscode/extensions/**/package.json", TargetKind.EXTENSION),
)


def matches_platform(requested: Platform, candidate: Platform) -> bool:
    if requested == Platform.ALL:
        return True
    if requested == Platform.GENERIC:
        return True
    return requested == candidate
