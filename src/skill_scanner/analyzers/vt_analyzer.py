from __future__ import annotations

import asyncio
import hashlib
import logging
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx

from skill_scanner.models.reports import VTReport, VTScanResult
from skill_scanner.models.targets import ScanTarget
from skill_scanner.utils.retry import RetryableError, async_retry_with_backoff

VT_BASE = "https://www.virustotal.com/api/v3"
RETRYABLE_STATUSES = {429, 500, 502, 503, 504}

logger = logging.getLogger(__name__)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_target(target: ScanTarget) -> tuple[Path, str]:
    temp_file = tempfile.NamedTemporaryFile(prefix="skill-scanner-", suffix=".zip", delete=False)
    zip_path = Path(temp_file.name)
    temp_file.close()

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for meta in target.files:
            file_path = Path(meta.path)
            if not file_path.exists() or not file_path.is_file():
                continue
            archive.write(file_path, arcname=meta.relative_path)

    return zip_path, _sha256_file(zip_path)


async def _request_with_retry(client: httpx.AsyncClient, method: str, url: str, **kwargs: Any) -> httpx.Response:
    async def _call() -> httpx.Response:
        try:
            response = await client.request(method=method, url=url, **kwargs)
        except httpx.TransportError as exc:
            raise RetryableError(f"Retryable VT transport error: {exc}") from exc
        if response.status_code in RETRYABLE_STATUSES:
            raise RetryableError(f"Retryable VT status {response.status_code}")
        return response

    return await async_retry_with_backoff(_call, attempts=6, base_delay=1.0, max_delay=20.0)


def _status_message(prefix: str, response: httpx.Response) -> str:
    return f"{prefix} (status={response.status_code})"


async def scan_with_vt(
    target: ScanTarget,
    api_key: str,
    timeout_s: int = 300,
    poll_interval_s: int = 10,
) -> VTScanResult:
    zip_path, sha256 = package_target(target)
    try:
        headers = {"x-apikey": api_key}
        async with httpx.AsyncClient(headers=headers, timeout=60.0) as client:
            logger.info("VirusTotal scan started for %s", target.entry_path)
            try:
                cached = await _request_with_retry(client, "GET", f"{VT_BASE}/files/{sha256}")
            except Exception as exc:
                return VTScanResult(error=f"VirusTotal cache lookup failed: {exc}")

            if cached.status_code == 200:
                return VTScanResult(report=_parse_vt_file(cached.json(), sha256))
            if cached.status_code != 404:
                return VTScanResult(error=_status_message("VirusTotal cache lookup failed", cached))

            with zip_path.open("rb") as handle:
                try:
                    upload = await _request_with_retry(
                        client,
                        "POST",
                        f"{VT_BASE}/files",
                        files={"file": (f"{sha256}.zip", handle, "application/zip")},
                    )
                except Exception as exc:
                    return VTScanResult(error=f"VirusTotal upload failed: {exc}")

            if upload.status_code >= 400:
                return VTScanResult(error=_status_message("VirusTotal upload failed", upload))

            try:
                analysis_id = upload.json().get("data", {}).get("id")
            except Exception:
                return VTScanResult(error="VirusTotal upload response was not valid JSON")

            if not analysis_id:
                return VTScanResult(error="VirusTotal upload response did not include analysis id")

            deadline = time.monotonic() + timeout_s
            timed_out = True
            while time.monotonic() < deadline:
                try:
                    analysis = await _request_with_retry(client, "GET", f"{VT_BASE}/analyses/{analysis_id}")
                except Exception as exc:
                    return VTScanResult(error=f"VirusTotal analysis polling failed: {exc}")

                if analysis.status_code >= 400:
                    return VTScanResult(error=_status_message("VirusTotal analysis polling failed", analysis))

                status = analysis.json().get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    timed_out = False
                    break
                await asyncio.sleep(max(1, poll_interval_s))

            try:
                report = await _request_with_retry(client, "GET", f"{VT_BASE}/files/{sha256}")
            except Exception as exc:
                if timed_out:
                    return VTScanResult(error=f"VirusTotal timed out and report fetch failed: {exc}")
                return VTScanResult(error=f"VirusTotal report fetch failed: {exc}")

            if report.status_code != 200:
                if timed_out:
                    return VTScanResult(
                        error=f"VirusTotal timed out after {timeout_s}s and report was unavailable (status={report.status_code})"
                    )
                return VTScanResult(error=_status_message("VirusTotal report fetch failed", report))

            parsed = _parse_vt_file(report.json(), sha256)
            if timed_out:
                return VTScanResult(
                    report=parsed,
                    error=f"VirusTotal timed out after {timeout_s}s; using latest available file verdict",
                )
            return VTScanResult(report=parsed)
    finally:
        zip_path.unlink(missing_ok=True)


def _parse_vt_file(payload: dict[str, object], sha256: str) -> VTReport:
    attrs = payload.get("data", {})
    if isinstance(attrs, dict):
        attrs = attrs.get("attributes", {})
    else:
        attrs = {}
    stats = attrs.get("last_analysis_stats", {}) if isinstance(attrs, dict) else {}
    if not isinstance(stats, dict):
        stats = {}
    results = attrs.get("last_analysis_results", {}) if isinstance(attrs, dict) else {}
    if not isinstance(results, dict):
        results = {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    analysis_total = 0
    for value in stats.values():
        if isinstance(value, bool):  # pragma: no cover - defensive safety net
            continue
        try:
            analysis_total += int(value or 0)
        except (TypeError, ValueError):  # pragma: no cover - defensive safety net
            continue

    detected = malicious + suspicious
    detection_ratio = (detected / analysis_total) if analysis_total > 0 else 0.0

    top_detections: list[str] = []
    for engine_name in sorted(results.keys()):
        engine_value = results.get(engine_name)
        if not isinstance(engine_value, dict):
            continue
        category = str(engine_value.get("category") or "").lower()
        if category not in {"malicious", "suspicious"}:
            continue
        verdict = str(engine_value.get("result") or category)
        top_detections.append(f"{engine_name}: {verdict}")
        if len(top_detections) >= 8:
            break

    return VTReport(
        sha256=sha256,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        analysis_total=analysis_total,
        detection_ratio=detection_ratio,
        top_detections=top_detections,
        permalink=f"https://www.virustotal.com/gui/file/{sha256}",
    )
