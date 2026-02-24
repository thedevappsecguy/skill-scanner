from __future__ import annotations

import asyncio
from types import SimpleNamespace

from skill_scanner.models.targets import Platform, ScanTarget, Scope, TargetKind
from skill_scanner.providers import openai_provider as openai_provider_module
from skill_scanner.providers.openai_provider import OpenAIProvider
from skill_scanner.utils.retry import RetryableError


class _TransientError(Exception):
    pass


class _NonRetryableError(Exception):
    pass


class _StatusError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"status={status_code}")
        self.status_code = status_code


class _Response:
    def __init__(self, content: str) -> None:
        self.choices = [SimpleNamespace(message=SimpleNamespace(content=content))]


class _DummyCompletions:
    def __init__(self, sequence: list[object]) -> None:
        self._sequence = sequence
        self.calls = 0

    async def create(self, **_kwargs):
        self.calls += 1
        value = self._sequence.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def _target() -> ScanTarget:
    return ScanTarget(
        id="target-1",
        kind=TargetKind.SKILL,
        platform=Platform.ALL,
        scope=Scope.REPO,
        entry_path="/tmp/SKILL.md",
        root_dir="/tmp",
        files=[],
    )


def _provider(sequence: list[object]) -> tuple[OpenAIProvider, _DummyCompletions]:
    completions = _DummyCompletions(sequence)
    provider = OpenAIProvider.__new__(OpenAIProvider)
    provider.api_key = "key"
    provider.model = "gpt-5.2"
    provider._client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider._retryable_error_types = (_TransientError,)
    provider._api_status_error_type = _StatusError
    return provider, completions


async def _fast_retry(
    fn,
    *,
    attempts: int = 5,
    base_delay: float = 0.5,
    max_delay: float = 10.0,
):
    del base_delay, max_delay
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return await fn()
        except RetryableError as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("unexpected retry state")


def test_openai_provider_retries_transient_errors(monkeypatch) -> None:
    monkeypatch.setattr(openai_provider_module, "async_retry_with_backoff", _fast_retry)
    provider, completions = _provider(
        [
            _TransientError("temporary"),
            _Response(
                '{"findings": [{"category": "configuration_risk", "severity": "low", "title": "a", "description": "b"}]}'
            ),
        ]
    )

    report = asyncio.run(provider.analyze(_target(), "payload"))

    assert completions.calls == 2
    assert report.error is None
    assert len(report.findings) == 1


def test_openai_provider_does_not_retry_non_retryable_error(monkeypatch) -> None:
    monkeypatch.setattr(openai_provider_module, "async_retry_with_backoff", _fast_retry)
    provider, completions = _provider([_NonRetryableError("fatal")])

    report = asyncio.run(provider.analyze(_target(), "payload"))

    assert completions.calls == 1
    assert report.findings == []
    assert report.error is not None
    assert "fatal" in report.error


def test_openai_provider_retries_status_500(monkeypatch) -> None:
    monkeypatch.setattr(openai_provider_module, "async_retry_with_backoff", _fast_retry)
    provider, completions = _provider([
        _StatusError(500),
        _Response('{"findings": []}'),
    ])

    report = asyncio.run(provider.analyze(_target(), "payload"))

    assert completions.calls == 2
    assert report.error is None
