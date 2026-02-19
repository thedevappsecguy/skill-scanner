from __future__ import annotations

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


class _DummyClient:
    def __init__(self, **_: Any) -> None:
        pass

    def __enter__(self) -> _DummyClient:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
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
    monkeypatch.setattr(vt_analyzer.httpx, "Client", _DummyClient)
    monkeypatch.setattr(
        vt_analyzer,
        "_request_with_retry",
        lambda *_args, **_kwargs: _DummyResponse(
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
        ),
    )

    report = vt_analyzer.scan_with_vt(target, api_key="test-key")
    assert report is not None
    assert not zip_path.exists()
