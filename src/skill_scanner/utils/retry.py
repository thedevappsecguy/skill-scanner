from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")

logger = logging.getLogger(__name__)


class RetryableError(Exception):
    pass


def _compute_delay(attempt: int, *, base_delay: float, max_delay: float) -> float:
    delay = min(max_delay, base_delay * (2**attempt)) + random.uniform(0.0, 0.5)
    return float(delay)


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
            sleep_for = _compute_delay(attempt, base_delay=base_delay, max_delay=max_delay)
            logger.info(
                "Retryable failure on attempt %s/%s, sleeping %.2fs: %s",
                attempt + 1,
                attempts,
                sleep_for,
                exc,
            )
            time.sleep(sleep_for)
    if last_exc is None:
        raise RuntimeError("retry_with_backoff failed without exception")
    raise last_exc


async def async_retry_with_backoff(
    fn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 5,
    base_delay: float = 0.5,
    max_delay: float = 10.0,
) -> T:
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return await fn()
        except RetryableError as exc:
            last_exc = exc
            if attempt == attempts - 1:
                break
            sleep_for = _compute_delay(attempt, base_delay=base_delay, max_delay=max_delay)
            logger.info(
                "Async retryable failure on attempt %s/%s, sleeping %.2fs: %s",
                attempt + 1,
                attempts,
                sleep_for,
                exc,
            )
            await asyncio.sleep(sleep_for)
    if last_exc is None:
        raise RuntimeError("async_retry_with_backoff failed without exception")
    raise last_exc
