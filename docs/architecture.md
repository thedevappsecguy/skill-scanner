# Architecture

`skill-scanner` flow:

1. Discover artifacts.
2. Run deterministic checks.
3. Run optional OpenAI analysis.
4. Run optional VirusTotal analysis.
5. Combine into risk score.
6. Render table, JSON, or SARIF.
