from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from skill_scanner.models.reports import AIReport
from skill_scanner.models.targets import ScanTarget


class LLMProvider(ABC):
    name: str = "unknown"

    def __init__(self, api_key: str | None, model: str) -> None:
        self.api_key = api_key
        self.model = model

    @abstractmethod
    async def analyze(self, target: ScanTarget, payload: str) -> AIReport:
        raise NotImplementedError


_REGISTRY: dict[str, Callable[[str | None, str], LLMProvider]] = {}


def register_provider(name: str) -> Callable[[type[LLMProvider]], type[LLMProvider]]:
    def decorator(cls: type[LLMProvider]) -> type[LLMProvider]:
        _REGISTRY[name] = cls
        return cls

    return decorator


def create_provider(name: str, api_key: str | None, model: str) -> LLMProvider:
    if name not in _REGISTRY:
        msg = f"Unsupported provider: {name}. Available: {', '.join(sorted(_REGISTRY))}"
        raise ValueError(msg)
    return _REGISTRY[name](api_key, model)


def available_providers() -> list[str]:
    return sorted(_REGISTRY)
