import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


class RetryableError(Exception):
    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


async def with_backoff(
    fn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 6,
    base: float = 1.0,
    cap: float = 30.0,
    on_retry: Callable[[int, float, Exception], None] | None = None,
) -> T:
    """Exponential backoff with full jitter; honours server-provided Retry-After."""
    for i in range(attempts):
        try:
            return await fn()
        except RetryableError as e:
            if i == attempts - 1:
                raise
            if e.retry_after is not None:
                delay = min(cap * 2, e.retry_after)
            else:
                delay = random.uniform(0, min(cap, base * (2**i))) + base * 0.25
            if on_retry:
                on_retry(i + 1, delay, e)
            await asyncio.sleep(delay)
    raise AssertionError("unreachable")
