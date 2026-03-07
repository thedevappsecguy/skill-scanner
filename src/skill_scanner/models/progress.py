from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ScanPhase(StrEnum):
    START = "start"
    VT_STARTED = "vt_started"
    VT_DONE = "vt_done"
    AI_STARTED = "ai_started"
    AI_DONE = "ai_done"
    SCORING = "scoring"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True)
class ScanProgressEvent:
    target_path: str
    phase: ScanPhase
