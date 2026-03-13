from __future__ import annotations

from pathlib import Path

from skill_scanner.config import load_settings


def _clear_env(monkeypatch) -> None:
    for name in ("SKILLSCAN_MODEL", "SKILLSCAN_API_KEY", "SKILLSCAN_BASE_URL", "VT_API_KEY"):
        monkeypatch.delenv(name, raising=False)


def test_load_settings_reads_generic_config_fields_from_cwd(monkeypatch, tmp_path: Path) -> None:
    _clear_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "skill-scanner.toml").write_text(
        '\n'.join(
            [
                'model = "anthropic/claude-sonnet-4-20250514"',
                'api_key = "cfg-key"',
                'base_url = "https://gateway.example.test"',
                'vt_api_key = "vt-key"',
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings()

    assert settings.model == "anthropic/claude-sonnet-4-20250514"
    assert settings.api_key == "cfg-key"
    assert settings.base_url == "https://gateway.example.test"
    assert settings.vt_api_key == "vt-key"


def test_load_settings_env_overrides_generic_fields(monkeypatch, tmp_path: Path) -> None:
    _clear_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "skill-scanner.toml").write_text(
        '\n'.join(
            [
                'model = "openai/gpt-5.4"',
                'api_key = "cfg-key"',
                'base_url = "https://config.example.test"',
                'vt_api_key = "cfg-vt"',
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SKILLSCAN_MODEL", "gemini/gemini-2.5-pro")
    monkeypatch.setenv("SKILLSCAN_API_KEY", "env-key")
    monkeypatch.setenv("SKILLSCAN_BASE_URL", "http://localhost:11434")
    monkeypatch.setenv("VT_API_KEY", "env-vt")

    settings = load_settings()

    assert settings.model == "gemini/gemini-2.5-pro"
    assert settings.api_key == "env-key"
    assert settings.base_url == "http://localhost:11434"
    assert settings.vt_api_key == "env-vt"


def test_load_settings_supports_local_model_without_api_key(monkeypatch, tmp_path: Path) -> None:
    _clear_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "skill-scanner.toml").write_text(
        '\n'.join(
            [
                'model = "ollama/llama3.1"',
                'base_url = "http://localhost:11434"',
            ]
        ),
        encoding="utf-8",
    )

    settings = load_settings()

    assert settings.model == "ollama/llama3.1"
    assert settings.api_key is None
    assert settings.base_url == "http://localhost:11434"


def test_load_settings_leaves_model_unset_when_not_configured(monkeypatch, tmp_path: Path) -> None:
    _clear_env(monkeypatch)
    monkeypatch.chdir(tmp_path)

    settings = load_settings()

    assert settings.model is None
