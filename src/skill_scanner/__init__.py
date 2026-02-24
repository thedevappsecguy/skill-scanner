"""skill_scanner package."""

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    __version__ = version("skill-scanner")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0+unknown"
