from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from skill_scanner.analyzers import vt_analyzer
from skill_scanner.models.targets import Platform, ScanTarget, Scope, TargetKind


class _DummyResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload


class _DummyAsyncClient:
    def __init__(self, **_: Any) -> None:
        pass

    async def __aenter__(self) -> _DummyAsyncClient:
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        return False


def test_scan_with_vt_removes_temp_zip_on_cached_result(tmp_path: Path, monkeypatch) -> None:
    zip_path = tmp_path / "scan.zip"
    zip_path.write_bytes(b"zip-bytes")

    target = ScanTarget(
        id="target-1",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path=str(tmp_path / "SKILL.md"),
        root_dir=str(tmp_path),
        files=[],
    )

    monkeypatch.setattr(vt_analyzer, "package_target", lambda _: (zip_path, "abc123"))
    monkeypatch.setattr(vt_analyzer.httpx, "AsyncClient", _DummyAsyncClient)

    async def _fake_request_with_retry(*_args, **_kwargs):
        return _DummyResponse(
            200,
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 1,
                            "undetected": 1,
                        }
                    }
                }
            },
        )

    monkeypatch.setattr(vt_analyzer, "_request_with_retry", _fake_request_with_retry)

    result = asyncio.run(vt_analyzer.scan_with_vt(target, api_key="test-key"))
    assert result.report is not None
    assert result.error is None
    assert not zip_path.exists()


def test_scan_with_vt_surfaces_error_context(monkeypatch, tmp_path: Path) -> None:
    zip_path = tmp_path / "scan.zip"
    zip_path.write_bytes(b"zip-bytes")

    target = ScanTarget(
        id="target-1",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path=str(tmp_path / "SKILL.md"),
        root_dir=str(tmp_path),
        files=[],
    )

    monkeypatch.setattr(vt_analyzer, "package_target", lambda _: (zip_path, "abc123"))
    monkeypatch.setattr(vt_analyzer.httpx, "AsyncClient", _DummyAsyncClient)

    async def _fake_request_with_retry(*_args, **_kwargs):
        return _DummyResponse(401, {})

    monkeypatch.setattr(vt_analyzer, "_request_with_retry", _fake_request_with_retry)

    result = asyncio.run(vt_analyzer.scan_with_vt(target, api_key="bad-key"))
    assert result.report is None
    assert result.error is not None
    assert "cache lookup failed" in result.error.lower()


def test_parse_vt_file_includes_detection_ratio_and_top_engines() -> None:
    parsed = vt_analyzer._parse_vt_file(
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "harmless": 4,
                        "undetected": 3,
                    },
                    "last_analysis_results": {
                        "EngineA": {"category": "malicious", "result": "Trojan.Generic"},
                        "EngineB": {"category": "suspicious", "result": "Riskware"},
                        "EngineC": {"category": "harmless", "result": "clean"},
                    },
                }
            }
        },
        sha256="abc123",
    )

    assert parsed.analysis_total == 10
    assert parsed.detection_ratio == 0.3
    assert parsed.top_detections == ["EngineA: Trojan.Generic", "EngineB: Riskware"]
