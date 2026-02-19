from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    HIDDEN_COMMANDS = "hidden_commands"
    PERMISSION_ESCALATION = "permission_escalation"
    SUPPLY_CHAIN_RISK = "supply_chain_risk"
    FILESYSTEM_ATTACK = "filesystem_attack"
    SOCIAL_ENGINEERING = "social_engineering"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    MALFORMED_SKILL = "malformed_skill"
    CONFIGURATION_RISK = "configuration_risk"


class Finding(BaseModel):
    source: str
    category: Category
    severity: Severity
    title: str
    description: str
    file_path: str | None = None
    line: int | None = None
    recommendation: str | None = None
    cwe: str | None = None
