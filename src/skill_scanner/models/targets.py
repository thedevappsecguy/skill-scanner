from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field


class TargetKind(StrEnum):
    SKILL = "skill"
    INSTRUCTION = "instruction"
    PROMPT = "prompt"
    AGENT = "agent"
    MCP = "mcp"
    COMMAND = "command"
    RULE = "rule"
    CONFIG = "config"
    EXTENSION = "extension"


class Scope(StrEnum):
    REPO = "repo"
    USER = "user"
    SYSTEM = "system"
    EXTENSION = "extension"


class Platform(StrEnum):
    ALL = "all"
    CODEX = "codex"
    CLAUDE = "claude"
    COPILOT = "copilot"
    CURSOR = "cursor"
    WINDSURF = "windsurf"
    GEMINI = "gemini"
    CLINE = "cline"
    OPENCODE = "opencode"
    VSCODE = "vscode"
    GENERIC = "generic"


class SkillFile(BaseModel):
    path: str
    relative_path: str
    size: int = 0


class ScanTarget(BaseModel):
    id: str
    kind: TargetKind
    platform: Platform
    scope: Scope
    entry_path: str
    root_dir: str
    files: list[SkillFile] = Field(default_factory=list)

    @property
    def path_obj(self) -> Path:
        return Path(self.entry_path)
