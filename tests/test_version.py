from __future__ import annotations

from importlib.metadata import version

from skill_scanner import __version__


def test_package_version_matches_metadata() -> None:
    assert __version__ == version("skill-scanner")
