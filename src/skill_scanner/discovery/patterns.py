from __future__ import annotations

from dataclasses import dataclass

from skill_scanner.models.targets import Platform, Scope, TargetKind


@dataclass(frozen=True)
class DiscoveryPattern:
    platform: Platform
    scope: Scope
    glob: str
    kind: TargetKind
    explicit_platform_only: bool = False


REPO_PATTERNS: tuple[DiscoveryPattern, ...] = (
    DiscoveryPattern(Platform.CODEX, Scope.REPO, ".agents/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CODEX, Scope.REPO, ".agents/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CODEX, Scope.REPO, "AGENTS.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, ".claude/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, ".claude/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, ".claude/agents/*.md", TargetKind.AGENT),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, "**/.claude/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, "**/.claude/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, "**/.claude/agents/*.md", TargetKind.AGENT),
    DiscoveryPattern(
        Platform.CLAUDE,
        Scope.REPO,
        ".claude/plugins/marketplaces/*/plugins/*/skills/*/SKILL.md",
        TargetKind.SKILL,
    ),
    DiscoveryPattern(
        Platform.CLAUDE,
        Scope.REPO,
        ".claude/plugins/marketplaces/*/external_plugins/*/skills/*/SKILL.md",
        TargetKind.SKILL,
    ),
    DiscoveryPattern(
        Platform.CLAUDE,
        Scope.REPO,
        ".claude/plugins/cache/**/skills/*/SKILL.md",
        TargetKind.SKILL,
    ),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, ".claude/commands/*.md", TargetKind.COMMAND),
    DiscoveryPattern(Platform.CLAUDE, Scope.REPO, "CLAUDE.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, ".github/copilot-instructions.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, ".github/instructions/**/*.instructions.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, "CLAUDE.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, "GEMINI.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, ".github/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, ".github/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, "AGENTS.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, "agents/*.agent.md", TargetKind.AGENT),
    DiscoveryPattern(Platform.COPILOT, Scope.REPO, "agents/**/*.agent.md", TargetKind.AGENT),
    DiscoveryPattern(Platform.CURSOR, Scope.REPO, ".cursor/rules/*.mdc", TargetKind.RULE),
    DiscoveryPattern(Platform.CURSOR, Scope.REPO, ".cursorrules", TargetKind.RULE),
    DiscoveryPattern(Platform.CURSOR, Scope.REPO, ".cursor/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CURSOR, Scope.REPO, ".cursor/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.WINDSURF, Scope.REPO, ".windsurf/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.WINDSURF, Scope.REPO, ".windsurf/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.GEMINI, Scope.REPO, "GEMINI.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.GEMINI, Scope.REPO, ".gemini/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.GEMINI, Scope.REPO, ".gemini/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.GEMINI, Scope.REPO, ".gemini/agents/*.md", TargetKind.AGENT),
    DiscoveryPattern(Platform.GEMINI, Scope.REPO, ".gemini/extensions/*/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.GEMINI, Scope.REPO, ".gemini/extensions/*/agents/*.md", TargetKind.AGENT),
    DiscoveryPattern(
        Platform.GEMINI,
        Scope.REPO,
        ".agents/skills/*/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(
        Platform.GEMINI,
        Scope.REPO,
        ".agents/skills/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(Platform.CLINE, Scope.REPO, ".cline/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLINE, Scope.REPO, ".cline/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLINE, Scope.REPO, ".clinerules/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLINE, Scope.REPO, ".clinerules/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.OPENCODE, Scope.REPO, ".opencode/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.OPENCODE, Scope.REPO, ".opencode/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.OPENCODE, Scope.REPO, ".opencode/agents/*.md", TargetKind.AGENT),
    DiscoveryPattern(
        Platform.OPENCODE,
        Scope.REPO,
        ".agents/skills/*/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(
        Platform.OPENCODE,
        Scope.REPO,
        ".agents/skills/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(
        Platform.OPENCODE,
        Scope.REPO,
        ".claude/skills/*/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(
        Platform.OPENCODE,
        Scope.REPO,
        ".claude/skills/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(Platform.VSCODE, Scope.REPO, ".github/prompts/**/*.prompt.md", TargetKind.PROMPT),
    DiscoveryPattern(Platform.VSCODE, Scope.REPO, ".github/agents/**/*.agent.md", TargetKind.AGENT),
)

USER_PATTERNS: tuple[DiscoveryPattern, ...] = (
    DiscoveryPattern(Platform.CLAUDE, Scope.USER, ".claude/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLAUDE, Scope.USER, ".claude/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLAUDE, Scope.USER, ".claude/agents/*.md", TargetKind.AGENT),
    DiscoveryPattern(
        Platform.CLAUDE,
        Scope.USER,
        ".claude/plugins/marketplaces/*/plugins/*/skills/*/SKILL.md",
        TargetKind.SKILL,
    ),
    DiscoveryPattern(
        Platform.CLAUDE,
        Scope.USER,
        ".claude/plugins/marketplaces/*/external_plugins/*/skills/*/SKILL.md",
        TargetKind.SKILL,
    ),
    DiscoveryPattern(
        Platform.CLAUDE,
        Scope.USER,
        ".claude/plugins/cache/**/skills/*/SKILL.md",
        TargetKind.SKILL,
    ),
    DiscoveryPattern(Platform.CLAUDE, Scope.USER, ".claude/CLAUDE.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.CODEX, Scope.USER, ".codex/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CODEX, Scope.USER, ".codex/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CODEX, Scope.USER, ".codex/skills/.system/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CODEX, Scope.USER, ".agents/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CODEX, Scope.USER, ".agents/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.COPILOT, Scope.USER, ".copilot/copilot-instructions.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.COPILOT, Scope.USER, ".copilot/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.COPILOT, Scope.USER, ".copilot/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.WINDSURF, Scope.USER, ".codeium/windsurf/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.WINDSURF, Scope.USER, ".codeium/windsurf/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.GEMINI, Scope.USER, ".gemini/GEMINI.md", TargetKind.INSTRUCTION),
    DiscoveryPattern(Platform.GEMINI, Scope.USER, ".gemini/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.GEMINI, Scope.USER, ".gemini/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.GEMINI, Scope.USER, ".gemini/agents/*.md", TargetKind.AGENT),
    DiscoveryPattern(Platform.GEMINI, Scope.USER, ".gemini/extensions/*/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.GEMINI, Scope.USER, ".gemini/extensions/*/agents/*.md", TargetKind.AGENT),
    DiscoveryPattern(
        Platform.GEMINI,
        Scope.USER,
        ".agents/skills/*/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(
        Platform.GEMINI,
        Scope.USER,
        ".agents/skills/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(Platform.CLINE, Scope.USER, ".cline/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLINE, Scope.USER, ".cline/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLINE, Scope.USER, ".clinerules/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CLINE, Scope.USER, ".clinerules/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.OPENCODE, Scope.USER, ".config/opencode/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.OPENCODE, Scope.USER, ".config/opencode/skills/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.OPENCODE, Scope.USER, ".config/opencode/agents/*.md", TargetKind.AGENT),
    DiscoveryPattern(
        Platform.OPENCODE,
        Scope.USER,
        ".agents/skills/*/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(
        Platform.OPENCODE,
        Scope.USER,
        ".agents/skills/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(
        Platform.OPENCODE,
        Scope.USER,
        ".claude/skills/*/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
    DiscoveryPattern(
        Platform.OPENCODE,
        Scope.USER,
        ".claude/skills/SKILL.md",
        TargetKind.SKILL,
        explicit_platform_only=True,
    ),
)

SYSTEM_PATTERNS: tuple[DiscoveryPattern, ...] = (
    DiscoveryPattern(Platform.CODEX, Scope.SYSTEM, "/etc/codex/skills/*/SKILL.md", TargetKind.SKILL),
    DiscoveryPattern(Platform.CODEX, Scope.SYSTEM, "/etc/codex/skills/SKILL.md", TargetKind.SKILL),
)

EXTENSION_PATTERNS: tuple[DiscoveryPattern, ...] = (
    DiscoveryPattern(Platform.VSCODE, Scope.EXTENSION, ".vscode/extensions/**/package.json", TargetKind.EXTENSION),
)


def matches_platform(requested: Platform, candidate: Platform, explicit_platform_only: bool = False) -> bool:
    if requested == Platform.ALL:
        return not explicit_platform_only
    if requested == Platform.GENERIC:
        return True
    return requested == candidate
