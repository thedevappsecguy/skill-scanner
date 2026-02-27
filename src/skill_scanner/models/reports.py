from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from skill_scanner.models.findings import Finding
from skill_scanner.models.targets import ScanTarget


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"


class AIReport(BaseModel):
    provider: str
    model: str
    findings: list[Finding] = Field(default_factory=list)
    raw_response: str | None = None
    error: str | None = None


class VTReport(BaseModel):
    sha256: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    analysis_total: int = 0
    detection_ratio: float = 0.0
    top_detections: list[str] = Field(default_factory=list)
    source: str = "virustotal"
    permalink: str | None = None


class VTScanResult(BaseModel):
    report: VTReport | None = None
    error: str | None = None


class SkillReport(BaseModel):
    target: ScanTarget
    deterministic_findings: list[Finding] = Field(default_factory=list)
    ai_findings: list[Finding] = Field(default_factory=list)
    vt_report: VTReport | None = None
    ai_score: float = 0.0
    ai_risk_level: RiskLevel = RiskLevel.CLEAN
    vt_score: float = 0.0
    vt_risk_level: RiskLevel = RiskLevel.CLEAN
    score: float = 0.0
    risk_level: RiskLevel = RiskLevel.CLEAN
    notes: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    scanned_targets: int
    reports: list[SkillReport]
    summary: dict[str, int]
