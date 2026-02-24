from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from skill_scanner.models.reports import AIReport, VTReport
from skill_scanner.models.targets import ScanTarget
from skill_scanner.providers.base import LLMProvider

logger = logging.getLogger(__name__)


@dataclass
class PayloadBuildResult:
    payload: str
    included_files: int
    skipped_due_to_limit: list[str] = field(default_factory=list)
    skipped_unreadable: list[str] = field(default_factory=list)
    used_chars: int = 0
    max_chars: int = 400_000


def build_payload(target: ScanTarget, max_chars: int = 400_000) -> PayloadBuildResult:
    chunks: list[str] = []
    total = 0
    included = 0
    skipped_due_to_limit: list[str] = []
    skipped_unreadable: list[str] = []

    for meta in target.files:
        path = Path(meta.path)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            skipped_unreadable.append(meta.relative_path)
            continue

        chunk = f"\n## FILE: {meta.relative_path}\n{text}\n"
        if total + len(chunk) > max_chars:
            skipped_due_to_limit.append(meta.relative_path)
            continue

        chunks.append(chunk)
        total += len(chunk)
        included += 1

    if skipped_due_to_limit:
        logger.info(
            "Payload truncated for %s: included=%s skipped=%s limit=%s",
            target.entry_path,
            included,
            len(skipped_due_to_limit),
            max_chars,
        )

    return PayloadBuildResult(
        payload="".join(chunks),
        included_files=included,
        skipped_due_to_limit=skipped_due_to_limit,
        skipped_unreadable=skipped_unreadable,
        used_chars=total,
        max_chars=max_chars,
    )


def _append_vt_context(payload: str, vt_report: VTReport | None) -> str:
    if vt_report is None:
        return payload
    vt_context = (
        "\n## VIRUSTOTAL_CONTEXT\n"
        f"sha256: {vt_report.sha256}\n"
        f"malicious: {vt_report.malicious}\n"
        f"suspicious: {vt_report.suspicious}\n"
        f"harmless: {vt_report.harmless}\n"
        f"undetected: {vt_report.undetected}\n"
        f"permalink: {vt_report.permalink or 'n/a'}\n"
    )
    return f"{payload}{vt_context}"


async def analyze_with_ai(
    target: ScanTarget,
    provider: LLMProvider,
    vt_report: VTReport | None = None,
) -> tuple[AIReport, PayloadBuildResult]:
    payload_result = build_payload(target)
    if not payload_result.payload.strip():
        return AIReport(provider=provider.name, model=provider.model, findings=[]), payload_result

    try:
        report = await provider.analyze(target, _append_vt_context(payload_result.payload, vt_report))
    except Exception as exc:  # pragma: no cover - defensive safety net
        report = AIReport(provider=provider.name, model=provider.model, findings=[], error=str(exc))

    return report, payload_result
