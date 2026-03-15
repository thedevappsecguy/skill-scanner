from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from skill_scanner.models.progress import ScanPhase, ScanProgressEvent

ProgressCallback = Callable[[ScanProgressEvent], None]


class ScanProgressDisplay(AbstractContextManager[ProgressCallback]):
    def __init__(self, console: Console, *, total_targets: int, enable_ai: bool, enable_vt: bool) -> None:
        self._console = console
        self._total_targets = total_targets
        self._stage_progress = _stage_progress_map(enable_ai=enable_ai, enable_vt=enable_vt)
        self._target_progress: dict[str, float] = {}
        self._task_id: TaskID | None = None
        self._progress = Progress(
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None, complete_style="magenta", finished_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TextColumn("[dim]{task.fields[detail]}"),
            console=console,
            transient=True,
            expand=True,
        )

    def __enter__(self) -> ProgressCallback:
        self._progress.start()
        self._task_id = self._progress.add_task(
            "Scanning...",
            total=float(max(self._total_targets, 1) * 100),
            detail="Preparing scan",
        )
        return self.update

    def __exit__(self, *args: object) -> bool | None:
        self._progress.stop()
        return None

    def update(self, event: ScanProgressEvent) -> None:
        if self._task_id is None:
            return

        current = self._target_progress.get(event.target_path, 0.0)
        next_value = max(current, self._stage_progress.get(event.phase, 100.0))
        self._target_progress[event.target_path] = next_value
        self._progress.update(
            self._task_id,
            completed=sum(self._target_progress.values()),
            detail=_detail_for_event(event),
        )


def _stage_progress_map(*, enable_ai: bool, enable_vt: bool) -> dict[ScanPhase, float]:
    ordered = [ScanPhase.START]
    if enable_vt:
        ordered.extend([ScanPhase.VT_STARTED, ScanPhase.VT_DONE])
    if enable_ai:
        ordered.extend([ScanPhase.LLM_STARTED, ScanPhase.LLM_DONE])
    ordered.extend([ScanPhase.SCORING, ScanPhase.DONE])

    total_steps = max(len(ordered) - 1, 1)
    progress = {
        phase: (index / total_steps) * 100.0
        for index, phase in enumerate(ordered)
    }
    progress[ScanPhase.FAILED] = 100.0
    return progress


def _detail_for_event(event: ScanProgressEvent) -> str:
    label = _short_target_label(event.target_path)
    descriptions = {
        ScanPhase.START: "Starting",
        ScanPhase.VT_STARTED: "VirusTotal",
        ScanPhase.VT_DONE: "VirusTotal complete",
        ScanPhase.LLM_STARTED: "LLM analysis",
        ScanPhase.LLM_DONE: "LLM analysis complete",
        ScanPhase.SCORING: "Risk classification",
        ScanPhase.DONE: "Completed",
        ScanPhase.FAILED: "Failed",
    }
    return f"{descriptions[event.phase]} {label}"


def _short_target_label(target_path: str) -> str:
    normalized = target_path.replace("\\", "/").rstrip("/")
    parts = [part for part in normalized.split("/") if part]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return normalized or target_path
