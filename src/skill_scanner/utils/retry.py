from __future__ import annotations

import random
import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


class RetryableError(Exception):
    pass


def retry_with_backoff(
    fn: Callable[[], T],
    *,
    attempts: int = 5,
    base_delay: float = 0.5,
    max_delay: float = 10.0,
) -> T:
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return fn()
        except RetryableError as exc:
            last_exc = exc
            if attempt == attempts - 1:
                break
            sleep_for = min(max_delay, base_delay * (2**attempt)) + random.uniform(0.0, 0.5)
            time.sleep(sleep_for)
    if last_exc is None:
        raise RuntimeError("retry_with_backoff failed without exception")
    raise last_exc
