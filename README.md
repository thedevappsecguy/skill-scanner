# skill-scanner

[![CI](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/ci.yml)
[![Publish TestPyPI](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/publish-testpypi.yml/badge.svg?branch=main)](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/publish-testpypi.yml)
[![Publish PyPI](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/release.yml/badge.svg)](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/release.yml)
[![zizmor](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/zizmor.yml/badge.svg?branch=main)](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/zizmor.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](https://github.com/thedevappsecguy/skill-scanner/blob/main/LICENSE)
[![PyPI](https://img.shields.io/pypi/v/skill-scanner.svg)](https://pypi.org/project/skill-scanner/)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](https://github.com/thedevappsecguy/skill-scanner/blob/main/SECURITY.md)

`skill-scanner` reviews AI skill and instruction artifacts for security risk using:
- OpenAI analysis
- VirusTotal analysis

## Requirements

- Python 3.11+
- [`uv`](https://docs.astral.sh/uv/)
- OpenAI and/or VirusTotal API key (at least one)

## Install (from source)

```bash
uv sync --all-extras --group dev
```

Run with:

```bash
uv run skill-scanner --help
```

Alias:

```bash
uv run skillscan --help
```

## What gets scanned

By default, `discover` and `scan` detect markdown-based skill/instruction artifacts (for example `SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `*.instructions.md`, `*.prompt.md`, `*.agent.md`, `.mdc`).

Validated skill locations also include:

- Windsurf: `.windsurf/skills/*/SKILL.md`, `~/.codeium/windsurf/skills/*/SKILL.md`
- Gemini CLI: `.gemini/skills/*/SKILL.md`, `~/.gemini/skills/*/SKILL.md` (`.agents/skills/*/SKILL.md` when `--platform gemini`)
- Cline: `.cline/skills/*/SKILL.md`, `.clinerules/skills/*/SKILL.md`, `~/.cline/skills/*/SKILL.md`, `~/.clinerules/skills/*/SKILL.md`
- OpenCode: `.opencode/skills/*/SKILL.md`, `~/.config/opencode/skills/*/SKILL.md` (`.agents/skills/*/SKILL.md` and `.claude/skills/*/SKILL.md` when `--platform opencode`)
- Claude marketplace/user variants: `.claude/skills/SKILL.md`, `.claude/skills/*/SKILL.md`, and
  `.claude/plugins/marketplaces/*/{plugins,external_plugins}/*/skills/*/SKILL.md`
- Documented agent profile locations: `.claude/agents/*.md`, `.gemini/agents/*.md`,
  `.gemini/extensions/*/agents/*.md`, `.opencode/agents/*.md`, `~/.config/opencode/agents/*.md`,
  `.github/agents/**/*.agent.md`, and `agents/*.agent.md`
- Skill discovery supports both flat and nested layouts: `skills/SKILL.md` and `skills/<name>/SKILL.md`

Use `--path` to target a specific file or folder.
`--path` discovery is deterministic and only emits files that match known discovery roots/patterns
(plus a direct `SKILL.md` at the provided path root). It does not treat arbitrary `*.md` files as targets.

Default discover behavior:

- `discover` attempts all scopes (`repo`, `user`, `system`, `extension`).
- `repo` scope is only active when your current directory is inside a git repository.
- Filesystem traversal errors are non-fatal; discovery returns partial results. Use `--verbose` to inspect warnings.

## Quick start

```bash
# See targets
uv run skill-scanner discover --format json

# Discover only user scope
uv run skill-scanner discover --scope user

# Show detailed discovery warnings
uv run skill-scanner discover --verbose

# Verify key/model configuration
uv run skill-scanner doctor

# Run live API checks (fails non-zero if checks fail)
uv run skill-scanner doctor --check

# Run a combined scan (if both keys are configured)
uv run skill-scanner scan --format summary
```

## Key configuration and analyzer selection

`scan` requires at least one analyzer enabled.

- If only `OPENAI_API_KEY` is available, AI runs and VT is disabled.
- If only `VT_API_KEY` is available, VT runs and AI is disabled.
- If both keys are available, VT findings are included and VT context is passed into AI analysis.
- You can disable either analyzer with `--no-ai` or `--no-vt`.
- If no model is configured, `gpt-5.2` is used as a fallback model.

Use `doctor --check` to verify the provider/key/model connectivity.

## API key safety

Use 1Password secret references instead of plaintext secrets:

```bash
OPENAI_API_KEY=op://Developer/OpenAI/api_key
VT_API_KEY=op://Developer/VirusTotal/api_key
```

Run the scanner through 1Password CLI so references are resolved at runtime:

```bash
op run --env-file=.env -- uv run skill-scanner scan --format summary
```

Security best practice:
- Prefer a 1Password Service Account scoped to only the vault/items required for scanning (least privilege).

Reference:
- https://developer.1password.com/docs/cli/secret-references/

## Output formats

`scan --format` supports:
- `table` (default)
- `summary`
- `json`
- `sarif`

You can write output to a file with `--output <path>`.

## Useful commands

```bash
# List providers
uv run skill-scanner providers

# Scan one path only
uv run skill-scanner scan --path ./some/skill/folder --format summary

# Increase scan concurrency (default: 8)
uv run skill-scanner scan --jobs 16 --format summary

# Enable verbose logs for troubleshooting
uv run skill-scanner scan --verbose --format summary

# List discovered targets without running analyzers
uv run skill-scanner scan --list-targets

# Discover targets from user scope only
uv run skill-scanner discover --scope user --format table

# Discover with detailed traversal diagnostics
uv run skill-scanner discover --verbose --format table

# Scan only selected discovered targets (repeat --target)
uv run skill-scanner scan --target /absolute/path/to/SKILL.md --target /absolute/path/to/AGENTS.md --format summary

# Filter to medium+
uv run skill-scanner scan --min-severity medium --format summary

# Non-zero exit if high+ findings exist
uv run skill-scanner scan --fail-on high --format summary

# Verbose doctor checks
uv run skill-scanner doctor --check --verbose
```

`--list-targets` can be used without API keys because it only runs discovery and exits.

## Discovery troubleshooting (macOS/Windows)

```bash
# macOS/Windows: default discover should complete without crashing
uv run skill-scanner discover --format table

# Scoped check: verify user skill paths only
uv run skill-scanner discover --scope user --format table
```

Windows known-path sanity check:
- create `%USERPROFILE%\\.clinerules\\skills\\demo\\SKILL.md`
- run `uv run skill-scanner discover --platform cline --scope user --format table`
- confirm the demo skill appears in output

## Exit behavior

- `0`: scan completed and fail threshold not hit
- `1`: `--fail-on` threshold matched
- `2`: no analyzers enabled (for example missing keys combined with flags), or `--target` did not match any discovered target

`doctor --check` exit behavior:

- `0`: all executed checks passed
- `1`: one or more checks failed

## Notes and truncation visibility

`scan` now surfaces per-target notes in table and summary output, including:

- analyzer failures (OpenAI or VirusTotal)
- payload truncation when files are skipped due to the 400k-character AI payload limit
- unreadable files excluded from payload construction

## Version bump workflow

Use `uv version` so version updates stay command-driven and lock state remains consistent.

```bash
# Patch bump (e.g., 0.1.2 -> 0.1.3)
uv version --bump patch

# Or set an explicit version
uv version 0.2.0
```

Notes:
- `pyproject.toml` is the canonical version source.
- `uv.lock` is generated by uv and should not be edited manually.
