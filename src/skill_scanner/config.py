from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import cast

from pydantic import BaseModel

from skill_scanner.models.targets import Platform, Scope


class Settings(BaseModel):
    provider: str = "openai"
    model: str = "gpt-5.2"
    openai_api_key: str | None = None
    vt_api_key: str | None = None
    default_platform: Platform = Platform.ALL
    default_scopes: set[Scope] = {Scope.REPO, Scope.USER, Scope.SYSTEM, Scope.EXTENSION}


def _load_config_file() -> dict[str, object]:
    candidates = [Path.cwd() / "skill-scanner.toml", Path.home() / ".config/skill-scanner/config.toml"]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            return tomllib.loads(candidate.read_text(encoding="utf-8"))
        except Exception:
            continue
    return {}


def _read_optional_str(payload: dict[str, object], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def load_settings(
    *,
    provider: str | None = None,
    model: str | None = None,
) -> Settings:
    payload: dict[str, object] = _load_config_file()

    cfg_provider = cast(str, payload.get("provider", "openai"))
    cfg_model = cast(str, payload.get("model", "gpt-5.2"))

    return Settings(
        provider=provider or os.getenv("SKILLSCAN_PROVIDER") or cfg_provider,
        model=model or os.getenv("SKILLSCAN_MODEL") or cfg_model,
        openai_api_key=os.getenv("OPENAI_API_KEY") or _read_optional_str(payload, "openai_api_key"),
        vt_api_key=os.getenv("VT_API_KEY") or _read_optional_str(payload, "vt_api_key"),
    )
