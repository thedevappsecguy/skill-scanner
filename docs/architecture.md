# Architecture

`skill-scanner` flow:

1. Discover scan targets from supported artifact patterns.
2. Execute target scans concurrently (bounded by `--jobs`, default `8`).
3. For each target, run VirusTotal analysis first (if enabled) and attach VT-derived findings.
4. Build AI payload from target files, tracking truncation and unreadable file metadata.
5. Run provider AI analysis (if enabled), including VT context in the prompt payload.
6. Combine deterministic + AI findings, attach notes (errors/truncation), and compute risk score.
7. Render output as table, summary, JSON, or SARIF.

Key reliability and observability behavior:

- OpenAI and VirusTotal network calls use exponential backoff retry for transient failures.
- Analyzer failures are soft-fail: scan continues, but target notes include explicit warning context.
- `doctor --check` runs live provider/API checks and exits non-zero when checks fail.
- `--verbose` enables INFO-level operational logging for scan lifecycle and retry events.
