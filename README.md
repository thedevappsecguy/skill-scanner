# skill-scanner

[![CI](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/ci.yml)
[![Publish TestPyPI](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/publish-testpypi.yml/badge.svg?branch=main)](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/publish-testpypi.yml)
[![zizmor](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/zizmor.yml/badge.svg?branch=main)](https://github.com/thedevappsecguy/skill-scanner/actions/workflows/zizmor.yml)

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

By default, `discover` and `scan` detect common skill/instruction files (for example `SKILL.md`, `AGENTS.md`, `*.instructions.md`, `*.prompt.md`, `.mdc`, and related artifacts).

Use `--path` to target a specific file or folder.

## Quick start

```bash
# See targets
uv run skill-scanner discover --format json

# Verify key/model configuration
uv run skill-scanner doctor

# Run a combined scan (if both keys are configured)
uv run skill-scanner scan --format summary
```

## Key configuration and analyzer selection

`scan` requires at least one analyzer enabled.

- If only `OPENAI_API_KEY` is available, AI runs and VT is disabled.
- If only `VT_API_KEY` is available, VT runs and AI is disabled.
- If both keys are available, VT findings are included and VT context is passed into AI analysis.
- You can disable either analyzer with `--no-ai` or `--no-vt`.

## API key safety

Use 1Password secret references instead of plaintext secrets:

```bash
OPENAI_API_KEY=op://Engineering/OpenAI/api_key
VT_API_KEY=op://Engineering/VirusTotal/api_key
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

# Filter to medium+
uv run skill-scanner scan --min-severity medium --format summary

# Non-zero exit if high+ findings exist
uv run skill-scanner scan --fail-on high --format summary
```

## Exit behavior

- `0`: scan completed and fail threshold not hit
- `1`: `--fail-on` threshold matched
- `2`: no analyzers enabled (for example missing keys combined with flags)
