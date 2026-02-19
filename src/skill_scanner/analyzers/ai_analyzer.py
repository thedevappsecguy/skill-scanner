from __future__ import annotations

from pathlib import Path

from skill_scanner.models.reports import AIReport, VTReport
from skill_scanner.models.targets import ScanTarget
from skill_scanner.providers.base import LLMProvider


def build_payload(target: ScanTarget, max_chars: int = 400_000) -> str:
    chunks: list[str] = []
    total = 0
    for meta in target.files:
        path = Path(meta.path)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        chunk = f"\n## FILE: {meta.relative_path}\n{text}\n"
        if total + len(chunk) > max_chars:
            continue
        chunks.append(chunk)
        total += len(chunk)
    return "".join(chunks)


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


def analyze_with_ai(target: ScanTarget, provider: LLMProvider, vt_report: VTReport | None = None) -> AIReport:
    payload = build_payload(target)
    if not payload.strip():
        return AIReport(provider=provider.name, model=provider.model, findings=[])
    return provider.analyze(target, _append_vt_context(payload, vt_report))
