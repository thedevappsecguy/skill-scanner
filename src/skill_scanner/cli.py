from __future__ import annotations

import logging
from collections import Counter
from pathlib import Path

import httpx
import typer
from rich.console import Console

from skill_scanner import __version__
from skill_scanner.analyzers.pipeline import run_scan
from skill_scanner.config import load_settings
from skill_scanner.discovery.finder import discover_targets
from skill_scanner.models.findings import Severity
from skill_scanner.models.reports import ScanReport, SkillReport
from skill_scanner.models.targets import Platform, ScanTarget, Scope
from skill_scanner.output.console import render_console_report
from skill_scanner.output.json_export import export_json_report
from skill_scanner.output.sarif_export import export_sarif_report
from skill_scanner.output.summary import render_summary_report
from skill_scanner.providers import available_providers, create_provider
from skill_scanner.scoring.risk import evaluate_risk

app = typer.Typer(
    help=(
        "Scan AI skills and instruction artifacts for risky behavior. "
        "Use `doctor` for API-key setup hints (OPENAI_API_KEY, VT_API_KEY)."
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
    format: str = typer.Option("table", help="table|json"),
) -> None:
    targets = discover_targets(path=path, platform=platform)
    if format == "json":
        console.print_json(data=[item.model_dump() for item in targets])
        return

    console.print(f"Discovered {len(targets)} targets")
    for item in targets:
        console.print(f"- {item.kind.value:<12} {item.scope.value:<9} {item.entry_path}")


@app.command()
def providers() -> None:
    names = available_providers()
    if not names:
        console.print("No providers are currently registered.")
        return
    console.print("Available providers:")
    for name in names:
        console.print(f"- {name}")


@app.command()
def doctor(
    provider: str | None = typer.Option(None, help="Provider name override (env: SKILLSCAN_PROVIDER)."),
    model: str | None = typer.Option(None, help="Model override (env: SKILLSCAN_MODEL)."),
    check: bool = typer.Option(False, "--check", help="Run live provider/API checks."),
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logs."),
) -> None:
    _configure_logging(verbose)
    settings = load_settings(provider=provider, model=model)

    console.print(f"provider={settings.provider}")
    console.print(f"model={settings.model}")
    console.print(f"OPENAI_API_KEY={'set' if settings.openai_api_key else 'missing'}")
    console.print(f"VT_API_KEY={'set' if settings.vt_api_key else 'missing'}")
    console.print("Hints:")
    console.print("- Set OpenAI key: export OPENAI_API_KEY=... (or put OPENAI_API_KEY=... in .env)")
    console.print("- Set VirusTotal key: export VT_API_KEY=... (or put VT_API_KEY=... in .env)")
    console.print("- `scan` requires at least one analyzer enabled (AI or VT).")
    console.print(
        "- Model fallback: when no model is configured, skill-scanner uses gpt-5.2. "
        "Use `doctor --check` to verify availability in your account."
    )

    if not check:
        return

    failures = 0
    checks_run = 0

    if settings.provider == "openai":
        checks_run += 1
        ok, message = _check_openai(settings.openai_api_key, settings.model)
        console.print(f"OpenAI check: {'PASS' if ok else 'FAIL'} - {message}")
        if not ok:
            failures += 1
    else:
        console.print(f"OpenAI check: SKIP - provider '{settings.provider}' is not openai")

    if settings.vt_api_key:
        checks_run += 1
        ok, message = _check_vt(settings.vt_api_key)
        console.print(f"VirusTotal check: {'PASS' if ok else 'FAIL'} - {message}")
        if not ok:
            failures += 1
    else:
        console.print("VirusTotal check: SKIP - VT_API_KEY is missing")

    logger.info("doctor --check completed: checks_run=%s failures=%s", checks_run, failures)
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
    provider: str | None = typer.Option(None, help="AI provider (env: SKILLSCAN_PROVIDER)."),
    model: str | None = typer.Option(None, help="Model name (env: SKILLSCAN_MODEL)."),
    no_ai: bool = typer.Option(False, help="Disable AI analysis (OpenAI key env: OPENAI_API_KEY)."),
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

    settings = load_settings(provider=provider, model=model)

    enable_ai, enable_vt = _resolve_analyzer_selection(settings, no_ai=no_ai, no_vt=no_vt)
    logger.info(
        "scan config: targets=%s jobs=%s enable_ai=%s enable_vt=%s provider=%s model=%s",
        len(targets),
        jobs,
        enable_ai,
        enable_vt,
        settings.provider,
        settings.model,
    )

    if not enable_ai and not enable_vt:
        console.print(
            "No analyzers enabled for scan. "
            "Set OPENAI_API_KEY and/or VT_API_KEY, or enable an analyzer by removing --no-ai/--no-vt."
        )
        raise typer.Exit(code=2)

    provider_impl = None
    if enable_ai:
        provider_impl = create_provider(settings.provider, settings.openai_api_key, settings.model)

    report = run_scan(
        targets,
        provider=provider_impl,
        vt_api_key=settings.vt_api_key if enable_vt else None,
        enable_ai=enable_ai,
        enable_vt=enable_vt,
        vt_timeout_s=vt_timeout,
        vt_poll_interval_s=vt_poll_interval,
        jobs=jobs,
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


def _check_openai(api_key: str | None, model: str) -> tuple[bool, str]:
    if not api_key:
        return False, "OPENAI_API_KEY is missing"

    try:
        from openai import OpenAI
    except ImportError:
        return False, "openai package is not installed (install skill-scanner[openai])"

    try:
        client = OpenAI(api_key=api_key)
        client.models.retrieve(model)
    except Exception as exc:
        return False, f"OpenAI check failed: {exc}"

    return True, f"Model '{model}' is accessible"


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

    if enable_ai and settings.provider == "openai" and not settings.openai_api_key:
        console.print(
            "AI analysis disabled: OPENAI_API_KEY is missing. "
            "Hint: set OPENAI_API_KEY (or use --no-ai)."
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
