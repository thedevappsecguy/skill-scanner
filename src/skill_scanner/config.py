from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel

from skill_scanner.models.targets import Platform, Scope


class Settings(BaseModel):
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None
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
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> Settings:
    payload: dict[str, object] = _load_config_file()

    return Settings(
        model=model or os.getenv("SKILLSCAN_MODEL") or _read_optional_str(payload, "model"),
        api_key=api_key or os.getenv("SKILLSCAN_API_KEY") or _read_optional_str(payload, "api_key"),
        base_url=base_url or os.getenv("SKILLSCAN_BASE_URL") or _read_optional_str(payload, "base_url"),
        vt_api_key=os.getenv("VT_API_KEY") or _read_optional_str(payload, "vt_api_key"),
    )
