# Contributing to skill-scanner

Thanks for helping improve the project! This guide keeps contributions quick and consistent.

## Getting set up
- Install Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).
- Install dependencies: `uv sync --all-extras --group dev`.
- Run the CLI locally: `uv run skill-scanner --help`.

## Before you open a PR
- Make changes on a branch; keep PRs focused and small.
- Add tests or fixtures when behavior changes.
- Run the checks:
  - `uv run ruff check`
  - `uv run mypy`
  - `uv run pytest`

## Opening a PR
- Describe the change, motivation, and testing done.
- Include any screenshots or logs if relevant.
- Make sure CI is green.

## Reporting issues
- Share a concise description, steps to reproduce, expected vs. actual behavior, and your environment (OS, Python, package version).

## Code of conduct
- Be respectful and constructive; follow the project’s security policy (`SECURITY.md`) and license (MIT).
