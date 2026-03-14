from __future__ import annotations

import asyncio
import logging
from collections import Counter
from contextlib import AbstractContextManager, nullcontext
from pathlib import Path

import httpx
import typer
from rich.console import Console

from skill_scanner import __version__
from skill_scanner.analyzers.pipeline import ProgressCallback, run_scan
from skill_scanner.config import load_settings
from skill_scanner.discovery.finder import discover_targets, discover_targets_with_diagnostics
from skill_scanner.models.findings import Severity
from skill_scanner.models.reports import ScanReport, SkillReport
from skill_scanner.models.targets import Platform, ScanTarget, Scope
from skill_scanner.output.console import render_console_report
from skill_scanner.output.json_export import export_json_report
from skill_scanner.output.progress import ScanProgressDisplay
from skill_scanner.output.sarif_export import export_sarif_report
from skill_scanner.output.summary import render_summary_report
from skill_scanner.providers import create_provider
from skill_scanner.providers.litellm_provider import check_litellm_connectivity
from skill_scanner.scoring.risk import evaluate_risk

app = typer.Typer(
    help=(
        "Scan AI skills and instruction artifacts for risky behavior. "
        "Use `doctor` for model/API setup hints (SKILLSCAN_MODEL, SKILLSCAN_API_KEY, "
        "SKILLSCAN_BASE_URL, VT_API_KEY)."
    ),
    no_args_is_help=True,
)
console = Console()
logger = logging.getLogger(__name__)


@app.callback(invoke_without_command=True)
def callback(
    version: bool = typer.Option(False, "--version", help="Show version and exit.", is_eager=True)
) -> None:
    if version:
        console.print(__version__)
        raise typer.Exit()


@app.command()
def discover(
    path: str | None = typer.Option(None, help="Custom file or directory path to scan."),
    platform: Platform = typer.Option(Platform.ALL, help="Platform to target."),
    scope: list[Scope] = typer.Option([], help="Scope filter, repeat for multiple."),
    format: str = typer.Option("table", help="table|json"),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logs."),
) -> None:
    _configure_logging(verbose)
    selected_scopes = set(scope) if scope else None
    targets, warnings = discover_targets_with_diagnostics(path=path, platform=platform, scopes=selected_scopes)
    if format == "json":
        console.print_json(data=[item.model_dump() for item in targets])
        return

    if warnings:
        if verbose:
            console.print(f"Discovery warnings: {len(warnings)}")
            for warning in warnings:
                console.print(f"- {warning}")
        else:
            console.print(f"Discovery warnings: {len(warnings)} (rerun with --verbose for details)")

    console.print(f"Discovered {len(targets)} targets")
    for item in targets:
        console.print(f"- {item.kind.value:<12} {item.scope.value:<9} {item.entry_path}")


@app.command()
def providers() -> None:
    console.print("AI model selection uses LiteLLM model strings.")
    console.print("Set SKILLSCAN_MODEL or pass --model with an explicit value from the LiteLLM catalog.")
    console.print("Examples:")
    console.print("- openai/gpt-5.4")
    console.print("- anthropic/<model-name>")
    console.print("- gemini/<model-name>")
    console.print("- ollama/<model-name>")
    console.print("Catalog: https://models.litellm.ai/")


@app.command()
def doctor(
    model: str | None = typer.Option(None, help="Model override (env: SKILLSCAN_MODEL)."),
    api_key: str | None = typer.Option(None, help="LLM API key override (env: SKILLSCAN_API_KEY)."),
    base_url: str | None = typer.Option(
        None,
        help="LLM base URL override (env: SKILLSCAN_BASE_URL).",
    ),
    check: bool = typer.Option(False, "--check", help="Run live provider/API checks."),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logs."),
) -> None:
    _configure_logging(verbose)
    settings = load_settings(model=model, api_key=api_key, base_url=base_url)

    console.print(f"model={settings.model or 'unset'}")
    console.print(f"SKILLSCAN_API_KEY={'set' if settings.api_key else 'missing'}")
    console.print(f"SKILLSCAN_BASE_URL={settings.base_url or 'unset'}")
    console.print(f"VT_API_KEY={'set' if settings.vt_api_key else 'missing'}")
    console.print("Hints:")
    console.print("- Hosted models: set SKILLSCAN_API_KEY=... via env, config file, or --api-key.")
    console.print("- Local/gateway models: set SKILLSCAN_BASE_URL=... plus a LiteLLM model string.")
    console.print("- Set VirusTotal key with VT_API_KEY via env, config file, or a secret manager wrapper.")
    console.print("- `.env` files are not auto-loaded; use `source`, `op run --env-file`, or your shell profile.")
    console.print("- `scan` requires at least one analyzer enabled (AI or VT).")
    console.print("- AI analysis requires an explicit SKILLSCAN_MODEL or --model value.")
    console.print("- No default model is applied; choose the model you want to use.")
    console.print("- Use `doctor --check` to verify availability in your account.")
    console.print("- Model catalog: https://models.litellm.ai/")

    if not check:
        return

    failures = 0
    checks_run = 0

    checks_run += 1
    ok, message = _check_llm(settings.model, settings.api_key, settings.base_url)
    console.print(f"LLM check: {'PASS' if ok else 'FAIL'} - {message}")
    if not ok:
        failures += 1

    if settings.vt_api_key:
        checks_run += 1
        ok, message = _check_vt(settings.vt_api_key)
        console.print(f"VirusTotal check: {'PASS' if ok else 'FAIL'} - {message}")
        if not ok:
            failures += 1
    else:
        console.print("VirusTotal check: SKIP - VT_API_KEY is missing")

    logger.info(
        "doctor --check completed: checks_run=%s failures=%s model=%s base_url=%s",
        checks_run,
        failures,
        settings.model or "unset",
        settings.base_url or "unset",
    )
    if failures > 0:
        raise typer.Exit(code=1)


@app.command()
def scan(
    path: str | None = typer.Option(None, help="Custom file or directory path to scan."),
    platform: Platform = typer.Option(Platform.ALL, help="Platform to target."),
    scope: list[Scope] = typer.Option([], help="Scope filter, repeat for multiple."),
    target: list[str] = typer.Option(
        [],
        "--target",
        help="Target entry path from discovery output, repeat for multiple.",
    ),
    list_targets: bool = typer.Option(False, help="List discovered scan targets and exit."),
    model: str | None = typer.Option(None, help="Model name (env: SKILLSCAN_MODEL)."),
    api_key: str | None = typer.Option(None, help="LLM API key override (env: SKILLSCAN_API_KEY)."),
    base_url: str | None = typer.Option(None, help="LLM base URL override (env: SKILLSCAN_BASE_URL)."),
    no_ai: bool = typer.Option(
        False,
        help="Disable AI analysis (requires generic LLM config via SKILLSCAN_* settings).",
    ),
    no_vt: bool = typer.Option(False, help="Disable VirusTotal analysis (key env: VT_API_KEY)."),
    jobs: int = typer.Option(8, min=1, help="Maximum concurrent targets to scan."),
    vt_timeout: int = typer.Option(300, min=1, help="VirusTotal analysis timeout in seconds."),
    vt_poll_interval: int = typer.Option(10, min=1, help="VirusTotal polling interval in seconds."),
    min_severity: Severity = typer.Option(Severity.INFO, help="Minimum severity to include."),
    fail_on: Severity | None = typer.Option(None, help="Exit non-zero if any finding >= severity."),
    format: str = typer.Option("table", help="table|json|sarif|summary"),
    output: str | None = typer.Option(None, help="Optional output file path."),
    no_color: bool = typer.Option(False, help="Disable color output."),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logs."),
) -> None:
    _configure_logging(verbose)

    selected_scopes = set(scope) if scope else {Scope.REPO, Scope.USER, Scope.SYSTEM, Scope.EXTENSION}
    show_progress = _should_show_scan_progress(format)
    if show_progress:
        with console.status("Discovering targets...", spinner="dots"):
            targets = discover_targets(path=path, platform=platform, scopes=selected_scopes)
    else:
        targets = discover_targets(path=path, platform=platform, scopes=selected_scopes)
    if target:
        targets = _filter_targets(targets, target)
        if not targets:
            console.print("No discovered targets matched --target values.")
            console.print("Use `skill-scanner scan --list-targets` to view valid target entry paths.")
            raise typer.Exit(code=2)

    if list_targets:
        _print_targets(targets)
        raise typer.Exit()

    settings = load_settings(model=model, api_key=api_key, base_url=base_url)

    enable_ai, enable_vt = _resolve_analyzer_selection(settings, no_ai=no_ai, no_vt=no_vt)
    logger.info(
        "scan config: targets=%s jobs=%s enable_ai=%s enable_vt=%s model=%s base_url=%s",
        len(targets),
        jobs,
        enable_ai,
        enable_vt,
        settings.model or "unset",
        settings.base_url or "unset",
    )

    if not enable_ai and not enable_vt:
        console.print(
            "No analyzers enabled for scan. "
            "Configure SKILLSCAN_API_KEY or SKILLSCAN_BASE_URL for AI analysis and/or VT_API_KEY "
            "for VirusTotal, or enable an analyzer by removing --no-ai/--no-vt."
        )
        raise typer.Exit(code=2)

    provider_impl = None
    if enable_ai:
        if settings.model is None:
            raise typer.Exit(code=2)
        provider_impl = create_provider(settings.api_key, settings.model, settings.base_url)

    with _scan_progress_context(
        total_targets=len(targets),
        enable_ai=enable_ai,
        enable_vt=enable_vt,
        enabled=show_progress,
    ) as progress_callback:
        report = run_scan(
            targets,
            provider=provider_impl,
            vt_api_key=settings.vt_api_key if enable_vt else None,
            enable_ai=enable_ai,
            enable_vt=enable_vt,
            vt_timeout_s=vt_timeout,
            vt_poll_interval_s=vt_poll_interval,
            jobs=jobs,
            progress_callback=progress_callback,
        )

    if min_severity != Severity.INFO:
        _apply_min_severity_filter(report, min_severity)

    if format == "json":
        payload = export_json_report(report, output)
        if not output:
            console.print(payload)
    elif format == "sarif":
        payload = export_sarif_report(report, output)
        if not output:
            console.print(payload)
    elif format == "summary":
        payload = render_summary_report(report, no_color=no_color)
        if output:
            Path(output).write_text(payload, encoding="utf-8")
    else:
        render_console_report(report, no_color=no_color)
        if output:
            Path(output).write_text(export_json_report(report), encoding="utf-8")

    if fail_on and _has_failures(report, fail_on):
        raise typer.Exit(code=1)


def _configure_logging(verbose: bool) -> None:
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        force=True,
    )


def _check_llm(model: str | None, api_key: str | None, base_url: str | None) -> tuple[bool, str]:
    return asyncio.run(check_litellm_connectivity(model=model, api_key=api_key, base_url=base_url))


def _should_show_scan_progress(format: str) -> bool:
    return console.is_terminal and format in {"table", "summary"}


def _scan_progress_context(
    *,
    total_targets: int,
    enable_ai: bool,
    enable_vt: bool,
    enabled: bool,
) -> AbstractContextManager[ProgressCallback | None]:
    if not enabled or total_targets <= 0:
        return nullcontext(None)
    return ScanProgressDisplay(
        console=console,
        total_targets=total_targets,
        enable_ai=enable_ai,
        enable_vt=enable_vt,
    )


def _check_vt(api_key: str) -> tuple[bool, str]:
    try:
        response = httpx.get(
            "https://www.virustotal.com/api/v3/users/current",
            headers={"x-apikey": api_key},
            timeout=20.0,
        )
    except Exception as exc:
        return False, f"VirusTotal connectivity failed: {exc}"

    if response.status_code == 200:
        return True, "API key is valid"

    return False, f"VirusTotal returned status {response.status_code}"


def _resolve_analyzer_selection(
    settings: object,
    *,
    no_ai: bool,
    no_vt: bool,
) -> tuple[bool, bool]:
    from skill_scanner.config import Settings

    if not isinstance(settings, Settings):
        return (not no_ai, not no_vt)

    enable_ai = not no_ai
    enable_vt = not no_vt

    if enable_ai and not settings.model:
        console.print(
            "AI analysis disabled: SKILLSCAN_MODEL is missing. "
            "Hint: set SKILLSCAN_MODEL (or use --no-ai)."
        )
        enable_ai = False

    if enable_ai and not settings.api_key and not settings.base_url:
        console.print(
            "AI analysis disabled: no LLM API key or base URL is configured. "
            "Hint: set SKILLSCAN_API_KEY for hosted models or SKILLSCAN_BASE_URL for local/gateway models "
            "(or use --no-ai)."
        )
        enable_ai = False

    if enable_vt and not settings.vt_api_key:
        console.print(
            "VirusTotal analysis disabled: VT_API_KEY is missing. "
            "Hint: set VT_API_KEY (or use --no-vt)."
        )
        enable_vt = False

    return enable_ai, enable_vt


def _severity_rank(value: Severity) -> int:
    order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return order[value]


def _apply_min_severity_filter(report: ScanReport, min_severity: Severity) -> None:
    filtered_reports: list[SkillReport] = []
    for item in report.reports:
        filtered = item.model_copy(
            update={
                "deterministic_findings": [
                    finding
                    for finding in item.deterministic_findings
                    if _severity_rank(finding.severity) >= _severity_rank(min_severity)
                ],
                "ai_findings": [
                    finding
                    for finding in item.ai_findings
                    if _severity_rank(finding.severity) >= _severity_rank(min_severity)
                ],
            }
        )
        filtered_reports.append(evaluate_risk(filtered))

    report.reports = filtered_reports
    report.summary = _build_summary(filtered_reports)


def _build_summary(reports: list[SkillReport]) -> dict[str, int]:
    counts = Counter(item.risk_level.value for item in reports)
    return {key: counts.get(key, 0) for key in ["critical", "high", "medium", "low", "clean"]}


def _filter_targets(targets: list[ScanTarget], requested: list[str]) -> list[ScanTarget]:
    selectors: set[str] = set()
    for requested_target in requested:
        raw = requested_target.strip()
        if not raw:
            continue
        selectors.add(raw)
        selectors.add(str(Path(raw).expanduser().resolve()))

    matched: list[ScanTarget] = []
    for discovered_target in targets:
        entry = str(Path(discovered_target.entry_path).resolve())
        if discovered_target.entry_path in selectors or entry in selectors:
            matched.append(discovered_target)
    return matched


def _print_targets(targets: list[ScanTarget]) -> None:
    console.print(f"Discovered {len(targets)} targets")
    for index, item in enumerate(targets, start=1):
        console.print(
            f"{index:>3}. {item.kind.value:<12} {item.platform.value:<8} {item.scope.value:<9} {item.entry_path}"
        )


def _has_failures(report: object, threshold: Severity) -> bool:
    if not isinstance(report, ScanReport):
        return False
    for item in report.reports:
        for finding in [*item.deterministic_findings, *item.ai_findings]:
            if _severity_rank(finding.severity) >= _severity_rank(threshold):
                return True
    return False
