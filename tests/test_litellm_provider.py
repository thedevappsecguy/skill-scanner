from __future__ import annotations

import asyncio
from types import SimpleNamespace

from skill_scanner.models.findings import Category, observed_pattern_specs_for_prompt
from skill_scanner.models.targets import Platform, ScanTarget, Scope, TargetKind
from skill_scanner.providers import litellm_provider as litellm_provider_module
from skill_scanner.providers.litellm_provider import LiteLLMProvider, check_litellm_connectivity
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


class _DummyCompletion:
    def __init__(self, sequence: list[object]) -> None:
        self._sequence = sequence
        self.calls = 0

    async def __call__(self, **_kwargs):
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


def _provider(sequence: list[object]) -> tuple[LiteLLMProvider, _DummyCompletion]:
    completion = _DummyCompletion(sequence)
    provider = LiteLLMProvider.__new__(LiteLLMProvider)
    provider.api_key = "key"
    provider.model = "openai/gpt-5.4"
    provider.base_url = None
    provider._litellm = SimpleNamespace(acompletion=completion)
    provider._retryable_error_types = (_TransientError,)
    return provider, completion


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


def test_litellm_provider_retries_transient_errors(monkeypatch) -> None:
    monkeypatch.setattr(litellm_provider_module, "async_retry_with_backoff", _fast_retry)
    provider, completion = _provider(
        [
            _TransientError("temporary"),
            _Response(
                '{"findings": [{"category": "configuration_risk", "severity": "low", "title": "a", "description": "b"}]}'
            ),
        ]
    )

    report = asyncio.run(provider.analyze(_target(), "payload"))

    assert completion.calls == 2
    assert report.error is None
    assert len(report.findings) == 1


def test_litellm_provider_does_not_retry_non_retryable_error(monkeypatch) -> None:
    monkeypatch.setattr(litellm_provider_module, "async_retry_with_backoff", _fast_retry)
    provider, completion = _provider([_NonRetryableError("fatal")])

    report = asyncio.run(provider.analyze(_target(), "payload"))

    assert completion.calls == 1
    assert report.findings == []
    assert report.error is not None
    assert "fatal" in report.error


def test_litellm_provider_retries_status_500(monkeypatch) -> None:
    monkeypatch.setattr(litellm_provider_module, "async_retry_with_backoff", _fast_retry)
    provider, completion = _provider([
        _StatusError(500),
        _Response('{"findings": []}'),
    ])

    report = asyncio.run(provider.analyze(_target(), "payload"))

    assert completion.calls == 2
    assert report.error is None


def test_system_prompt_includes_observed_pattern_descriptions() -> None:
    prompt = litellm_provider_module.SYSTEM_PROMPT
    for item in observed_pattern_specs_for_prompt():
        assert f"- {item.category.value}: {item.description}" in prompt
    assert "mcp_attack" not in prompt
    assert "mcp_config" not in prompt
    assert "best-practice remediation" in prompt
    assert "specific to instruction files and skills" in prompt
    assert 'return `{ "findings": [] }`' in prompt


def test_litellm_provider_maps_legacy_category_aliases(monkeypatch) -> None:
    monkeypatch.setattr(litellm_provider_module, "async_retry_with_backoff", _fast_retry)
    provider, _ = _provider(
        [
            _Response(
                '{"findings": [{"category": "data_exfiltration", "severity": "high", "title": "exfil", "description": "legacy alias"}]}'
            )
        ]
    )

    report = asyncio.run(provider.analyze(_target(), "payload"))

    assert report.error is None
    assert len(report.findings) == 1
    assert report.findings[0].category == Category.EXFILTRATION
    assert report.findings[0].source == "openai"


def test_litellm_provider_unknown_category_falls_back_to_configuration_risk(monkeypatch) -> None:
    monkeypatch.setattr(litellm_provider_module, "async_retry_with_backoff", _fast_retry)
    provider, _ = _provider(
        [
            _Response(
                '{"findings": [{"category": "unexpected_category", "severity": "medium", "title": "unknown", "description": "unknown"}]}'
            )
        ]
    )

    report = asyncio.run(provider.analyze(_target(), "payload"))

    assert report.error is None
    assert len(report.findings) == 1
    assert report.findings[0].category == Category.CONFIGURATION_RISK


def test_litellm_provider_disables_telemetry_and_callbacks_on_init(monkeypatch) -> None:
    fake_module = SimpleNamespace(
        telemetry=True,
        callbacks=["x"],
        success_callback=["y"],
        failure_callback=["z"],
        _async_success_callback=["a"],
        _async_failure_callback=["b"],
        input_callback=["c"],
        service_callback=["d"],
        APIConnectionError=_TransientError,
        APIError=_TransientError,
        RateLimitError=_TransientError,
        ServiceUnavailableError=_TransientError,
        Timeout=_TransientError,
        InternalServerError=_TransientError,
        acompletion=None,
    )
    monkeypatch.setattr(litellm_provider_module, "_load_litellm_module", lambda: fake_module)

    provider = LiteLLMProvider(api_key="key", model="openai/gpt-5.4")

    assert provider._litellm.telemetry is False
    assert provider._litellm.callbacks == []
    assert provider._litellm.success_callback == []
    assert provider._litellm.failure_callback == []
    assert provider._litellm._async_success_callback == []
    assert provider._litellm._async_failure_callback == []
    assert provider._litellm.input_callback == []
    assert provider._litellm.service_callback == []


def test_check_litellm_connectivity_requires_api_key_or_base_url() -> None:
    ok, message = asyncio.run(
        check_litellm_connectivity(model="openai/gpt-5.4", api_key=None, base_url=None)
    )
    assert ok is False
    assert "SKILLSCAN_API_KEY" in message


def test_check_litellm_connectivity_succeeds(monkeypatch) -> None:
    async def _acompletion(**_kwargs):
        return _Response("ok")

    fake_module = SimpleNamespace(
        telemetry=True,
        callbacks=[],
        success_callback=[],
        failure_callback=[],
        _async_success_callback=[],
        _async_failure_callback=[],
        input_callback=[],
        service_callback=[],
        APIConnectionError=_TransientError,
        APIError=_TransientError,
        RateLimitError=_TransientError,
        ServiceUnavailableError=_TransientError,
        Timeout=_TransientError,
        InternalServerError=_TransientError,
        acompletion=_acompletion,
    )
    monkeypatch.setattr(litellm_provider_module, "_load_litellm_module", lambda: fake_module)

    ok, message = asyncio.run(
        check_litellm_connectivity(
            model="ollama/llama3.1",
            api_key=None,
            base_url="http://localhost:11434",
        )
    )

    assert ok is True
    assert "ollama/llama3.1" in message


def test_provider_source_uses_model_prefix() -> None:
    assert litellm_provider_module._provider_source("openai/gpt-5.4") == "openai"
    assert litellm_provider_module._provider_source("ollama/llama3.1") == "ollama"
    assert litellm_provider_module._provider_source("gpt-5.4") == "openai"
