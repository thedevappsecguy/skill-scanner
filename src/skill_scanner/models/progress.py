from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ScanPhase(StrEnum):
    START = "start"
    VT_STARTED = "vt_started"
    VT_DONE = "vt_done"
    LLM_STARTED = "llm_started"
    LLM_DONE = "llm_done"
    SCORING = "scoring"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True)
class ScanProgressEvent:
    target_path: str
    phase: ScanPhase
