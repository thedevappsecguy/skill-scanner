# skill-scanner

`skill-scanner` scans agent skills and instruction artifacts for risky patterns using OpenAI and VirusTotal analysis (no hardcoded static rule checks in scan flow).

## Install

```bash
uv sync --all-extras --group dev
```

## CLI

Primary command:

```bash
skill-scanner --help
```

Alias:

```bash
skillscan --help
```

## Quick start

```bash
skill-scanner scan --format summary
skill-scanner discover --format json
skill-scanner providers
skill-scanner doctor
```

## API keys and analyzer selection

Set keys via environment variables:

```bash
export OPENAI_API_KEY=...
export VT_API_KEY=...
```

Or place them in a local `.env` file (which should be gitignored):

```bash
OPENAI_API_KEY=...
VT_API_KEY=...
```

Run `skill-scanner doctor` to verify key status and see setup hints.

`scan` behavior with partial keys:

- If only `OPENAI_API_KEY` is set, AI analysis runs and VirusTotal is auto-disabled with a CLI hint.
- If only `VT_API_KEY` is set, VirusTotal runs and AI is auto-disabled with a CLI hint.
- If both are enabled, VirusTotal intel is passed into AI context and VT verdict findings appear in ranked findings.
- You can force disable either analyzer with `--no-ai` or `--no-vt`.
- If neither analyzer is enabled, `scan` exits with guidance to add keys or re-enable an analyzer.
