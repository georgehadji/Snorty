def backoff_delay(attempt: int, *, base: float = 2.0, cap: float = 60.0) -> float:
    """Seconds to wait before restart number `attempt` (1-based): 2, 4, 8 ... cap."""
    return min(cap, base * (1 << (attempt - 1)))


def should_give_up(failures: int, max_restarts: int) -> bool:
    return failures >= max_restarts
