from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(StrEnum):
    EXTERNAL_DOWNLOAD = "external_download"
    PROMPT_INJECTION = "prompt_injection"
    SSRF_CLOUD = "ssrf_cloud"
    COMMAND_EXECUTION = "command_execution"
    SUPPLY_CHAIN = "supply_chain"
    EXFILTRATION = "exfiltration"
    CREDENTIAL_LEAK = "credential_leak"
    INDIRECT_INJECTION = "indirect_injection"
    TOXIC_FLOW = "toxic_flow"
    THIRD_PARTY_CONTENT = "third_party_content"
    CONFIGURATION_RISK = "configuration_risk"

    # Compatibility aliases for existing consumers; values resolve to canonical categories.
    DATA_EXFILTRATION = "exfiltration"
    HIDDEN_COMMANDS = "command_execution"
    PERMISSION_ESCALATION = "toxic_flow"
    SUPPLY_CHAIN_RISK = "supply_chain"
    FILESYSTEM_ATTACK = "command_execution"
    SOCIAL_ENGINEERING = "indirect_injection"
    CREDENTIAL_HARVESTING = "credential_leak"
    MALFORMED_SKILL = "configuration_risk"


@dataclass(frozen=True)
class CategorySpec:
    category: Category
    description: str


_OBSERVED_PATTERN_SPECS: tuple[CategorySpec, ...] = (
    CategorySpec(
        category=Category.EXTERNAL_DOWNLOAD,
        description="Skills that download or reference external files, URLs, or resources.",
    ),
    CategorySpec(
        category=Category.PROMPT_INJECTION,
        description="Skills with patterns that could enable prompt injection attacks.",
    ),
    CategorySpec(
        category=Category.SSRF_CLOUD,
        description="Server-side request forgery risks targeting cloud metadata or internal services.",
    ),
    CategorySpec(
        category=Category.COMMAND_EXECUTION,
        description="Skills that execute shell commands, system calls, or subprocess operations.",
    ),
    CategorySpec(
        category=Category.SUPPLY_CHAIN,
        description="Supply chain risks: typosquatting, dependency confusion, or untrusted packages.",
    ),
    CategorySpec(
        category=Category.EXFILTRATION,
        description="Skills with patterns that could leak sensitive data to external endpoints.",
    ),
    CategorySpec(
        category=Category.CREDENTIAL_LEAK,
        description="Skills that handle, expose, or hardcode credentials and secrets.",
    ),
    CategorySpec(
        category=Category.INDIRECT_INJECTION,
        description="Indirect prompt injection via external data sources.",
    ),
    CategorySpec(
        category=Category.TOXIC_FLOW,
        description="Multi-step flows that combine benign tools into dangerous chains.",
    ),
    CategorySpec(
        category=Category.THIRD_PARTY_CONTENT,
        description="Skills that load or embed untrusted third-party content.",
    ),
)

_CATEGORY_ALIASES: dict[str, Category] = {
    "external_download": Category.EXTERNAL_DOWNLOAD,
    "prompt_injection": Category.PROMPT_INJECTION,
    "ssrf_cloud": Category.SSRF_CLOUD,
    "command_execution": Category.COMMAND_EXECUTION,
    "supply_chain": Category.SUPPLY_CHAIN,
    "exfiltration": Category.EXFILTRATION,
    "credential_leak": Category.CREDENTIAL_LEAK,
    "indirect_injection": Category.INDIRECT_INJECTION,
    "toxic_flow": Category.TOXIC_FLOW,
    "third_party_content": Category.THIRD_PARTY_CONTENT,
    "configuration_risk": Category.CONFIGURATION_RISK,
    # Legacy aliases
    "data_exfiltration": Category.EXFILTRATION,
    "hidden_commands": Category.COMMAND_EXECUTION,
    "permission_escalation": Category.TOXIC_FLOW,
    "supply_chain_risk": Category.SUPPLY_CHAIN,
    "filesystem_attack": Category.COMMAND_EXECUTION,
    "social_engineering": Category.INDIRECT_INJECTION,
    "credential_harvesting": Category.CREDENTIAL_LEAK,
    "malformed_skill": Category.CONFIGURATION_RISK,
}


def observed_pattern_specs_for_prompt() -> list[CategorySpec]:
    return list(_OBSERVED_PATTERN_SPECS)


def category_specs_for_prompt() -> list[CategorySpec]:
    """Backward-compatible alias for observed pattern prompt specs."""
    return observed_pattern_specs_for_prompt()


def canonicalize_category(raw: str) -> Category:
    normalized = raw.strip().lower().replace("-", "_")
    if not normalized:
        return Category.CONFIGURATION_RISK
    return _CATEGORY_ALIASES.get(normalized, Category.CONFIGURATION_RISK)


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
