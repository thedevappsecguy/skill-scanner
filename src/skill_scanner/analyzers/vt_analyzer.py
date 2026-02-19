from __future__ import annotations

import hashlib
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx

from skill_scanner.models.reports import VTReport
from skill_scanner.models.targets import ScanTarget
from skill_scanner.utils.retry import RetryableError, retry_with_backoff

VT_BASE = "https://www.virustotal.com/api/v3"


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


def _request_with_retry(client: httpx.Client, method: str, url: str, **kwargs: Any) -> httpx.Response:
    def _call() -> httpx.Response:
        response = client.request(method=method, url=url, **kwargs)
        if response.status_code in {429, 500, 502, 503, 504}:
            raise RetryableError(f"Retryable VT status {response.status_code}")
        return response

    return retry_with_backoff(_call, attempts=6, base_delay=1.0, max_delay=20.0)


def scan_with_vt(
    target: ScanTarget,
    api_key: str,
    timeout_s: int = 300,
    poll_interval_s: int = 10,
) -> VTReport | None:
    zip_path, sha256 = package_target(target)
    try:
        headers = {"x-apikey": api_key}
        with httpx.Client(headers=headers, timeout=60.0) as client:
            cached = _request_with_retry(client, "GET", f"{VT_BASE}/files/{sha256}")
            if cached.status_code == 200:
                return _parse_vt_file(cached.json(), sha256)

            with zip_path.open("rb") as handle:
                upload = _request_with_retry(
                    client,
                    "POST",
                    f"{VT_BASE}/files",
                    files={"file": (f"{sha256}.zip", handle, "application/zip")},
                )
            if upload.status_code >= 400:
                return None

            analysis_id = upload.json().get("data", {}).get("id")
            if not analysis_id:
                return None

            deadline = time.time() + timeout_s
            while time.time() < deadline:
                analysis = _request_with_retry(client, "GET", f"{VT_BASE}/analyses/{analysis_id}")
                if analysis.status_code >= 400:
                    break
                status = analysis.json().get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    break
                time.sleep(max(1, poll_interval_s))

            report = _request_with_retry(client, "GET", f"{VT_BASE}/files/{sha256}")
            if report.status_code == 200:
                return _parse_vt_file(report.json(), sha256)
        return None
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
    return VTReport(
        sha256=sha256,
        malicious=int(stats.get("malicious", 0) or 0),
        suspicious=int(stats.get("suspicious", 0) or 0),
        harmless=int(stats.get("harmless", 0) or 0),
        undetected=int(stats.get("undetected", 0) or 0),
        permalink=f"https://www.virustotal.com/gui/file/{sha256}",
    )
