from __future__ import annotations

import re
from pathlib import Path

from skill_scanner.models.findings import Category, Finding, Severity
from skill_scanner.models.targets import ScanTarget, TargetKind
from skill_scanner.validation.frontmatter import parse_frontmatter

NAME_RE = re.compile(r"^(?!-)(?!.*--)[a-z0-9-]{1,64}(?<!-)$")


def validate_skill_target(target: ScanTarget) -> list[Finding]:
    findings: list[Finding] = []
    if target.kind != TargetKind.SKILL:
        return findings

    skill_path = Path(target.entry_path)
    try:
        text = skill_path.read_text(encoding="utf-8")
    except Exception as exc:
        return [
            Finding(
                source="deterministic",
                category=Category.MALFORMED_SKILL,
                severity=Severity.HIGH,
                title="Unreadable SKILL.md",
                description=f"Unable to read SKILL.md: {exc}",
                file_path=target.entry_path,
                recommendation="Ensure the file exists and is UTF-8 encoded.",
            )
        ]

    parsed = parse_frontmatter(text)
    if parsed is None:
        findings.append(
            Finding(
                source="deterministic",
                category=Category.MALFORMED_SKILL,
                severity=Severity.HIGH,
                title="Missing or invalid YAML frontmatter",
                description="SKILL.md must start with YAML frontmatter bounded by --- lines.",
                file_path=target.entry_path,
                recommendation="Add valid YAML frontmatter with name and description.",
            )
        )
        return findings

    frontmatter, _ = parsed
    name = frontmatter.get("name")
    description = frontmatter.get("description")
    parent = skill_path.parent.name

    if not isinstance(name, str) or not NAME_RE.match(name):
        findings.append(
            Finding(
                source="deterministic",
                category=Category.MALFORMED_SKILL,
                severity=Severity.MEDIUM,
                title="Invalid skill name",
                description="`name` must be lowercase alphanumeric and hyphen only, 1-64 chars.",
                file_path=target.entry_path,
                recommendation="Update frontmatter `name` to a valid slug.",
            )
        )
    if isinstance(name, str) and name != parent:
        findings.append(
            Finding(
                source="deterministic",
                category=Category.MALFORMED_SKILL,
                severity=Severity.MEDIUM,
                title="Skill directory and name mismatch",
                description=f"Directory `{parent}` does not match frontmatter name `{name}`.",
                file_path=target.entry_path,
                recommendation="Rename the directory or change frontmatter `name`.",
            )
        )
    if not isinstance(description, str) or not (1 <= len(description) <= 1024):
        findings.append(
            Finding(
                source="deterministic",
                category=Category.MALFORMED_SKILL,
                severity=Severity.LOW,
                title="Invalid or missing description",
                description="`description` should be present and between 1 and 1024 characters.",
                file_path=target.entry_path,
                recommendation="Add a concise description to frontmatter.",
            )
        )

    allowed = frontmatter.get("allowed-tools")
    if isinstance(allowed, list) and any(str(item).lower() in {"bash", "network", "write"} for item in allowed):
        findings.append(
            Finding(
                source="deterministic",
                category=Category.PERMISSION_ESCALATION,
                severity=Severity.MEDIUM,
                title="Elevated tool access requested",
                description="Skill requests powerful tools in `allowed-tools`.",
                file_path=target.entry_path,
                recommendation="Restrict allowed tools to least privilege.",
            )
        )

    return findings
