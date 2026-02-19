from __future__ import annotations

import json
from typing import Any

from skill_scanner.models.findings import Category, Finding, Severity
from skill_scanner.models.reports import AIReport
from skill_scanner.models.targets import ScanTarget
from skill_scanner.providers.base import LLMProvider, register_provider
from skill_scanner.utils.retry import RetryableError, retry_with_backoff

SYSTEM_PROMPT = """
You are a security reviewer for AI agent artifacts.
Return strict JSON with key `findings` as a list of objects with:
category,severity,title,description,file_path,line,recommendation,cwe.
Valid severities: critical,high,medium,low,info.
Valid categories: prompt_injection,data_exfiltration,hidden_commands,permission_escalation,supply_chain_risk,filesystem_attack,social_engineering,credential_harvesting,malformed_skill,configuration_risk.
Do not return prose outside JSON.
""".strip()


def _normalize_finding(item: dict[str, Any]) -> Finding:
    category = item.get("category", "configuration_risk")
    severity = item.get("severity", "low")
    return Finding(
        source="openai",
        category=Category(category),
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
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Install optional dependency: pip install 'skill-scanner[openai]'") from exc
        self._client = OpenAI(api_key=api_key)

    def analyze(self, target: ScanTarget, payload: str) -> AIReport:
        def _call() -> str:
            response = self._client.chat.completions.create(
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
            choice = response.choices[0]
            content = choice.message.content
            if not content:
                raise RetryableError("OpenAI returned empty response")
            return content

        try:
            raw = retry_with_backoff(_call)
            data = json.loads(raw)
        except Exception as exc:
            return AIReport(provider=self.name, model=self.model, findings=[], raw_response=str(exc))

        findings: list[Finding] = []
        for item in data.get("findings", []):
            if not isinstance(item, dict):
                continue
            try:
                findings.append(_normalize_finding(item))
            except Exception:
                continue
        return AIReport(provider=self.name, model=self.model, findings=findings, raw_response=raw)
