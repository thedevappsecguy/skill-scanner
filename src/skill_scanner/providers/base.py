from __future__ import annotations

from abc import ABC, abstractmethod

from skill_scanner.models.reports import AIReport
from skill_scanner.models.targets import ScanTarget


class LLMProvider(ABC):
    name: str = "litellm"

    def __init__(self, *, api_key: str | None, model: str, base_url: str | None = None) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url

    @abstractmethod
    async def analyze(self, target: ScanTarget, payload: str) -> AIReport:
        raise NotImplementedError


def create_provider(api_key: str | None, model: str, base_url: str | None = None) -> LLMProvider:
    from skill_scanner.providers.litellm_provider import LiteLLMProvider

    return LiteLLMProvider(api_key=api_key, model=model, base_url=base_url)
