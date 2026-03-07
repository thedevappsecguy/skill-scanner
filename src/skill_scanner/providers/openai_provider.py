from __future__ import annotations

import json
import logging
from typing import Any

from skill_scanner.models.findings import (
    Finding,
    Severity,
    canonicalize_category,
    observed_pattern_specs_for_prompt,
)
from skill_scanner.models.reports import AIReport
from skill_scanner.models.targets import ScanTarget
from skill_scanner.providers.base import LLMProvider, register_provider
from skill_scanner.utils.retry import RetryableError, async_retry_with_backoff


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

logger = logging.getLogger(__name__)


def _normalize_finding(item: dict[str, Any]) -> Finding:
    category = canonicalize_category(str(item.get("category", "configuration_risk")))
    severity = str(item.get("severity", "low"))
    return Finding(
        source="openai",
        category=category,
        severity=Severity(severity),
        title=str(item.get("title", "AI finding")),
        description=str(item.get("description", "")),
        file_path=item.get("file_path"),
        line=item.get("line"),
        recommendation=item.get("recommendation"),
        cwe=item.get("cwe"),
    )


@register_provider("openai")
class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, api_key: str | None, model: str) -> None:
        super().__init__(api_key=api_key, model=model)
        if not api_key:
            raise ValueError("OPENAI_API_KEY is required for OpenAI analysis")
        from openai import (
            APIConnectionError,
            APIStatusError,
            APITimeoutError,
            AsyncOpenAI,
            InternalServerError,
            RateLimitError,
        )

        self._client = AsyncOpenAI(api_key=api_key)
        self._api_status_error_type = APIStatusError
        self._retryable_error_types: tuple[type[BaseException], ...] = (
            APIConnectionError,
            APITimeoutError,
            RateLimitError,
            InternalServerError,
        )

    def _is_retryable_openai_error(self, exc: Exception) -> bool:
        if isinstance(exc, self._retryable_error_types):
            return True
        if isinstance(exc, self._api_status_error_type):
            status = getattr(exc, "status_code", None)
            if isinstance(status, int):
                return status in {408, 409, 429, 500, 502, 503, 504}
        return False

    async def analyze(self, target: ScanTarget, payload: str) -> AIReport:
        async def _call() -> str:
            try:
                response = await self._client.chat.completions.create(
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
                )
            except Exception as exc:
                if self._is_retryable_openai_error(exc):
                    raise RetryableError(f"Retryable OpenAI error: {exc}") from exc
                raise

            choice = response.choices[0]
            content = choice.message.content
            if not content:
                raise RetryableError("OpenAI returned empty response")
            return content

        try:
            raw = await async_retry_with_backoff(_call)
            data = json.loads(raw)
        except Exception as exc:
            logger.warning("OpenAI analysis failed for %s: %s", target.entry_path, exc)
            return AIReport(provider=self.name, model=self.model, findings=[], error=str(exc))

        findings: list[Finding] = []
        for item in data.get("findings", []):
            if not isinstance(item, dict):
                continue
            try:
                findings.append(_normalize_finding(item))
            except Exception:
                continue
        return AIReport(provider=self.name, model=self.model, findings=findings, raw_response=raw)
