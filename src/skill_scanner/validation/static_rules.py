from __future__ import annotations

import re
from pathlib import Path

from skill_scanner.models.findings import Category, Finding, Severity
from skill_scanner.models.targets import ScanTarget

RULES: tuple[tuple[re.Pattern[str], Category, Severity, str, str], ...] = (
    (
        re.compile(r"ignore (all|any) previous instructions|bypass safety", re.IGNORECASE),
        Category.PROMPT_INJECTION,
        Severity.HIGH,
        "Prompt injection pattern",
        "Remove instructions that attempt to override system behavior.",
    ),
    (
        re.compile(r"https?://[^\s]*(webhook|requestbin|ngrok|pastebin|discord)", re.IGNORECASE),
        Category.DATA_EXFILTRATION,
        Severity.HIGH,
        "Potential exfiltration endpoint",
        "Validate and restrict outbound endpoints.",
    ),
    (
        re.compile(r"base64\s+-d|frombase64string|exec\(|eval\(", re.IGNORECASE),
        Category.HIDDEN_COMMANDS,
        Severity.HIGH,
        "Possible obfuscated command execution",
        "Avoid dynamic execution and decode paths.",
    ),
    (
        re.compile(r"\.\./\.\./|/etc/passwd|\.ssh/id_rsa", re.IGNORECASE),
        Category.FILESYSTEM_ATTACK,
        Severity.HIGH,
        "Possible sensitive file access",
        "Constrain file operations to safe workspace directories.",
    ),
    (
        re.compile(r"OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY", re.IGNORECASE),
        Category.CREDENTIAL_HARVESTING,
        Severity.MEDIUM,
        "Credential handling reference",
        "Ensure secrets are never exfiltrated or logged.",
    ),
)


def _first_line(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


def run_static_rules(target: ScanTarget) -> list[Finding]:
    findings: list[Finding] = []
    for file_meta in target.files:
        file_path = Path(file_meta.path)
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, category, severity, title, recommendation in RULES:
            match = pattern.search(text)
            if not match:
                continue
            findings.append(
                Finding(
                    source="deterministic",
                    category=category,
                    severity=severity,
                    title=title,
                    description=f"Matched pattern `{pattern.pattern}`.",
                    file_path=str(file_path),
                    line=_first_line(text, match.start()),
                    recommendation=recommendation,
                )
            )
    return findings
