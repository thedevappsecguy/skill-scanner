from __future__ import annotations

import importlib
import json
import logging
from typing import Any

import httpx

from skill_scanner.models.findings import (
    Finding,
    Severity,
    canonicalize_category,
    observed_pattern_specs_for_prompt,
)
from skill_scanner.models.reports import AIReport
from skill_scanner.models.targets import ScanTarget
from skill_scanner.providers.base import LLMProvider
from skill_scanner.utils.retry import RetryableError, async_retry_with_backoff

logger = logging.getLogger(__name__)


def _build_system_prompt() -> str:
    category_lines = "\n".join(
        f"- {item.category.value}: {item.description}"
        for item in observed_pattern_specs_for_prompt()
    )
    return (
        "You are a security reviewer for AI agent artifacts.\n"
        "Return strict JSON with key `findings` as a list of objects with:\n"
        "category,severity,title,description,file_path,line,recommendation,cwe.\n"
        "Valid severities: critical,high,medium,low,info.\n"
        "Observed patterns (category values):\n"
        f"{category_lines}\n"
        "For each finding, include actionable best-practice remediation in `recommendation` based on that finding's evidence.\n"
        "Remediation must be specific to instruction files and skills, not generic advice.\n"
        "Prefer concrete controls such as command/tool allowlists, explicit user confirmation for execution/network actions, "
        "least-privilege permissions, domain allowlisting, pinned versions, and checksum/signature verification.\n"
        "When `VIRUSTOTAL_CONTEXT` is present:\n"
        "- Use it as corroborating evidence to prioritize and adjust severity/confidence of file-backed findings.\n"
        "- Prefer findings that reference concrete risky content in the payload (`file_path` and `line` when possible).\n"
        "- Do not emit a standalone finding that only repeats VT verdict counts or permalink without additional file-level evidence.\n"
        "If no actionable risks are present, return `{ \"findings\": [] }`.\n"
        "Do not return prose outside JSON."
    )


SYSTEM_PROMPT = _build_system_prompt()


def _load_litellm_module() -> Any:
    try:
        return importlib.import_module("litellm")
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency should be present
        raise RuntimeError("litellm package is unavailable; reinstall skill-scanner") from exc


def _configure_litellm_runtime(litellm_module: Any) -> None:
    litellm_module.telemetry = False
    for attr in (
        "callbacks",
        "success_callback",
        "failure_callback",
        "_async_success_callback",
        "_async_failure_callback",
        "input_callback",
        "service_callback",
    ):
        if hasattr(litellm_module, attr):
            setattr(litellm_module, attr, [])


def _provider_source(model: str) -> str:
    prefix, _, _remainder = model.partition("/")
    normalized = prefix.strip().lower()
    if not _:
        if normalized.startswith(("gpt-", "o1", "o3", "o4")):
            return "openai"
        return normalized or "ai"
    return normalized or "ai"


def _normalize_finding(item: dict[str, Any], *, source: str) -> Finding:
    category = canonicalize_category(str(item.get("category", "configuration_risk")))
    severity = str(item.get("severity", "low"))
    return Finding(
        source=source,
        category=category,
        severity=Severity(severity),
        title=str(item.get("title", "AI finding")),
        description=str(item.get("description", "")),
        file_path=item.get("file_path"),
        line=item.get("line"),
        recommendation=item.get("recommendation"),
        cwe=item.get("cwe"),
    )


def _response_content(response: Any) -> str:
    try:
        choice = response.choices[0]
        content = choice.message.content
    except Exception as exc:  # pragma: no cover - defensive fallback
        raise RetryableError(f"LiteLLM returned unexpected response shape: {exc}") from exc

    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            text = getattr(item, "text", None)
            if isinstance(text, str):
                parts.append(text)
                continue
            if isinstance(item, dict):
                dict_text = item.get("text")
                if isinstance(dict_text, str):
                    parts.append(dict_text)
        joined = "".join(parts).strip()
        if joined:
            return joined
    raise RetryableError("LiteLLM returned empty response")


class LiteLLMProvider(LLMProvider):
    name = "litellm"

    def __init__(self, *, api_key: str | None, model: str, base_url: str | None = None) -> None:
        super().__init__(api_key=api_key, model=model, base_url=base_url)
        if not model.strip():
            raise ValueError("A LiteLLM model string is required for AI analysis")

        litellm_module = _load_litellm_module()
        _configure_litellm_runtime(litellm_module)
        self._litellm = litellm_module
        self._retryable_error_types: tuple[type[BaseException], ...] = tuple(
            error_type
            for error_type in (
                getattr(litellm_module, "APIConnectionError", None),
                getattr(litellm_module, "APIError", None),
                getattr(litellm_module, "RateLimitError", None),
                getattr(litellm_module, "ServiceUnavailableError", None),
                getattr(litellm_module, "Timeout", None),
                getattr(litellm_module, "InternalServerError", None),
                httpx.TransportError,
                httpx.TimeoutException,
                TimeoutError,
            )
            if isinstance(error_type, type)
        )

    def _is_retryable_error(self, exc: Exception) -> bool:
        if isinstance(exc, self._retryable_error_types):
            return True
        status = getattr(exc, "status_code", None)
        if isinstance(status, int):
            return status in {408, 409, 429, 500, 502, 503, 504}
        return False

    def _request_kwargs(self) -> dict[str, object]:
        kwargs: dict[str, object] = {}
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return kwargs

    async def analyze(self, target: ScanTarget, payload: str) -> AIReport:
        async def _call() -> str:
            try:
                response = await self._litellm.acompletion(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": f"Target: {target.entry_path}\n\nPayload:\n{payload}",
                        },
                    ],
                    response_format={"type": "json_object"},
                    timeout=90,
                    **self._request_kwargs(),
                )
            except Exception as exc:
                if self._is_retryable_error(exc):
                    raise RetryableError(f"Retryable LiteLLM error: {exc}") from exc
                raise

            return _response_content(response)

        try:
            raw = await async_retry_with_backoff(_call)
            data = json.loads(raw)
        except Exception as exc:
            logger.warning("LiteLLM analysis failed for %s: %s", target.entry_path, exc)
            return AIReport(provider=self.name, model=self.model, findings=[], error=str(exc))

        findings: list[Finding] = []
        source = _provider_source(self.model)
        for item in data.get("findings", []):
            if not isinstance(item, dict):
                continue
            try:
                findings.append(_normalize_finding(item, source=source))
            except Exception:
                continue
        return AIReport(provider=self.name, model=self.model, findings=findings, raw_response=raw)


async def check_litellm_connectivity(
    *,
    model: str | None,
    api_key: str | None,
    base_url: str | None,
) -> tuple[bool, str]:
    if model is None or not model.strip():
        return False, "SKILLSCAN_MODEL is missing"
    if not api_key and not base_url:
        return (
            False,
            "No LLM API key or base URL configured. Set SKILLSCAN_API_KEY for hosted models "
            "or SKILLSCAN_BASE_URL for local/gateway models.",
        )

    try:
        provider = LiteLLMProvider(api_key=api_key, model=model, base_url=base_url)
        await provider._litellm.acompletion(
            model=provider.model,
            messages=[{"role": "user", "content": "Reply with exactly OK and nothing else."}],
            max_tokens=8,
            timeout=30,
            **provider._request_kwargs(),
        )
    except Exception as exc:
        return False, f"LiteLLM check failed: {exc}"

    location = f" via {base_url}" if base_url else ""
    return True, f"Model '{model}' responded successfully{location}"
