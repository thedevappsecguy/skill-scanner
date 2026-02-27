from __future__ import annotations

import asyncio
import logging
from collections import Counter

from skill_scanner.analyzers.ai_analyzer import PayloadBuildResult, analyze_with_ai
from skill_scanner.analyzers.vt_analyzer import scan_with_vt
from skill_scanner.models.findings import Category, Finding, Severity
from skill_scanner.models.reports import AIReport, ScanReport, SkillReport, VTReport
from skill_scanner.models.targets import ScanTarget
from skill_scanner.providers.base import LLMProvider
from skill_scanner.scoring.risk import evaluate_risk

logger = logging.getLogger(__name__)


def run_scan(
    targets: list[ScanTarget],
    *,
    provider: LLMProvider | None,
    vt_api_key: str | None,
    enable_ai: bool,
    enable_vt: bool,
    vt_timeout_s: int = 300,
    vt_poll_interval_s: int = 10,
    jobs: int = 8,
) -> ScanReport:
    return asyncio.run(
        run_scan_async(
            targets,
            provider=provider,
            vt_api_key=vt_api_key,
            enable_ai=enable_ai,
            enable_vt=enable_vt,
            vt_timeout_s=vt_timeout_s,
            vt_poll_interval_s=vt_poll_interval_s,
            jobs=jobs,
        )
    )


async def run_scan_async(
    targets: list[ScanTarget],
    *,
    provider: LLMProvider | None,
    vt_api_key: str | None,
    enable_ai: bool,
    enable_vt: bool,
    vt_timeout_s: int = 300,
    vt_poll_interval_s: int = 10,
    jobs: int = 8,
) -> ScanReport:
    max_jobs = max(1, jobs)
    semaphore = asyncio.Semaphore(max_jobs)

    async def _bounded_scan(target: ScanTarget) -> SkillReport:
        async with semaphore:
            try:
                return await _scan_target(
                    target,
                    provider=provider,
                    vt_api_key=vt_api_key,
                    enable_ai=enable_ai,
                    enable_vt=enable_vt,
                    vt_timeout_s=vt_timeout_s,
                    vt_poll_interval_s=vt_poll_interval_s,
                )
            except Exception as exc:  # pragma: no cover - defensive safety net
                logger.exception("Unhandled scan failure for %s", target.entry_path)
                return evaluate_risk(
                    SkillReport(target=target, notes=[f"Internal scan failure: {exc}"])
                )

    tasks = [asyncio.create_task(_bounded_scan(target)) for target in targets]
    reports = await asyncio.gather(*tasks)

    summary_counter = Counter(item.risk_level.value for item in reports)
    summary = {key: summary_counter.get(key, 0) for key in ["critical", "high", "medium", "low", "clean"]}

    return ScanReport(
        scanned_targets=len(targets),
        reports=reports,
        summary=summary,
    )


async def _scan_target(
    target: ScanTarget,
    *,
    provider: LLMProvider | None,
    vt_api_key: str | None,
    enable_ai: bool,
    enable_vt: bool,
    vt_timeout_s: int,
    vt_poll_interval_s: int,
) -> SkillReport:
    logger.info("Scanning target: %s", target.entry_path)

    deterministic: list[Finding] = []
    notes: list[str] = []

    vt_report: VTReport | None = None
    if enable_vt and vt_api_key:
        vt_result = await scan_with_vt(
            target,
            vt_api_key,
            timeout_s=vt_timeout_s,
            poll_interval_s=vt_poll_interval_s,
        )
        vt_report = vt_result.report
        if vt_result.error:
            notes.append(f"VirusTotal: {vt_result.error}")
        deterministic.extend(_vt_findings(vt_report))

    ai_report = AIReport(provider="disabled", model="n/a", findings=[])
    if enable_ai and provider is not None:
        ai_report, payload_result = await analyze_with_ai(target, provider, vt_report=vt_report)
        notes.extend(_payload_notes(payload_result))
        filtered_ai_findings, dropped_count = _filter_vt_only_ai_findings(ai_report.findings, vt_report)
        if dropped_count > 0:
            notes.append(
                f"AI output normalized: removed {dropped_count} duplicate VirusTotal-only finding(s)."
            )
        if dropped_count > 0:
            ai_report = ai_report.model_copy(update={"findings": filtered_ai_findings})
        if ai_report.error:
            notes.append(f"AI analysis: {ai_report.error}")

    report = SkillReport(
        target=target,
        deterministic_findings=deterministic,
        ai_findings=ai_report.findings,
        vt_report=vt_report,
        notes=notes,
    )

    evaluated = evaluate_risk(report)
    logger.info(
        "Finished target %s: risk=%s findings=%s notes=%s",
        target.entry_path,
        evaluated.risk_level.value,
        len(evaluated.deterministic_findings) + len(evaluated.ai_findings),
        len(evaluated.notes),
    )
    return evaluated


def _payload_notes(payload_result: PayloadBuildResult) -> list[str]:
    notes: list[str] = []

    if payload_result.skipped_due_to_limit:
        sample = ", ".join(payload_result.skipped_due_to_limit[:5])
        remaining = len(payload_result.skipped_due_to_limit) - 5
        suffix = "" if remaining <= 0 else f", +{remaining} more"
        notes.append(
            "AI payload truncated at "
            f"{payload_result.max_chars} characters; "
            f"{len(payload_result.skipped_due_to_limit)} file(s) excluded: {sample}{suffix}"
        )

    if payload_result.skipped_unreadable:
        sample = ", ".join(payload_result.skipped_unreadable[:5])
        remaining = len(payload_result.skipped_unreadable) - 5
        suffix = "" if remaining <= 0 else f", +{remaining} more"
        notes.append(
            f"{len(payload_result.skipped_unreadable)} file(s) could not be read for AI payload: {sample}{suffix}"
        )

    return notes


def _vt_findings(vt_report: object) -> list[Finding]:
    if not isinstance(vt_report, VTReport):
        return []

    findings: list[Finding] = []
    if vt_report.malicious > 0:
        severity = Severity.CRITICAL if vt_report.malicious >= 3 else Severity.HIGH
        findings.append(
            Finding(
                source="virustotal",
                category=Category.SUPPLY_CHAIN_RISK,
                severity=severity,
                title="VirusTotal detected malicious verdicts",
                description=(
                    "VirusTotal marked the uploaded artifact as malicious by "
                    f"{vt_report.malicious} engine(s)."
                ),
                recommendation=(
                    "Treat this artifact as high risk and review the VirusTotal report before use. "
                    f"Details: {vt_report.permalink or 'n/a'}"
                ),
            )
        )
    elif vt_report.suspicious > 0:
        findings.append(
            Finding(
                source="virustotal",
                category=Category.SUPPLY_CHAIN_RISK,
                severity=Severity.MEDIUM,
                title="VirusTotal detected suspicious verdicts",
                description=(
                    "VirusTotal marked the uploaded artifact as suspicious by "
                    f"{vt_report.suspicious} engine(s)."
                ),
                recommendation=(
                    "Review the VirusTotal detections before trusting this artifact. "
                    f"Details: {vt_report.permalink or 'n/a'}"
                ),
            )
        )

    return findings


def _filter_vt_only_ai_findings(
    findings: list[Finding],
    vt_report: VTReport | None,
) -> tuple[list[Finding], int]:
    if vt_report is None or (vt_report.malicious + vt_report.suspicious) == 0:
        return findings, 0

    filtered: list[Finding] = []
    dropped = 0
    for finding in findings:
        text = " ".join(
            [
                finding.title or "",
                finding.description or "",
                finding.recommendation or "",
            ]
        ).lower()
        mentions_vt = "virustotal" in text or "vt context" in text
        has_file_evidence = bool(finding.file_path) or finding.line is not None

        if mentions_vt and not has_file_evidence:
            dropped += 1
            continue
        filtered.append(finding)

    return filtered, dropped
