from dataclasses import dataclass, field
from pathlib import Path

MAX_CHUNK = 8 * 1024 * 1024  # bytes read per call, so a huge backlog is never held in memory
HEAD = 64  # leading bytes of the file kept to tell a replaced file from a grown one
SEEN_MAX = 4096  # distinct recent lines remembered for numbering identical ones


@dataclass(frozen=True, slots=True)
class TailState:
    offset: int = 0  # bytes of the file consumed so far, including `pending`
    pending: bytes = b""  # trailing bytes of an unfinished line
    head: bytes = b""  # the file's first bytes at the last read; a change means a new file
    # The most recent lines with how often each appeared. Snort stamps alerts to the microsecond,
    # so two alerts can print as identical lines; this counts them apart so neither is mistaken
    # for a repeat of the other.
    seen: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class TailResult:
    lines: list[str]
    state: TailState
    rotated: bool
    # Per line: 0 for the first of its kind, then 1, 2, ...
    ties: list[int] = field(default_factory=list)


def _tie_indexes(
    lines: list[str], seen: tuple[tuple[str, int], ...]
) -> tuple[list[int], tuple[tuple[str, int], ...]]:
    counts = dict(seen)
    ties: list[int] = []
    for line in lines:
        n = counts.pop(line, 0)  # re-inserted below, so the dict stays in recency order
        ties.append(n)
        counts[line] = n + 1
    return ties, tuple(counts.items())[-SEEN_MAX:]


def read_new_lines(path: Path, state: TailState) -> TailResult:
    """Return the complete lines added since `state`, at most MAX_CHUNK bytes' worth.
    Call again until it returns no lines to read the rest.

    A file shorter than our offset, or one that no longer starts with the bytes it started with,
    counts as rotated or replaced and is re-read from 0. A file rewritten with the same first
    bytes is not told apart (an alert line starts with its own microsecond stamp, so this
    needs the same first alert twice).
    """
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return TailResult([], state, False)
    with path.open("rb") as fh:
        head = fh.read(HEAD)
        rotated = size < state.offset or head[: len(state.head)] != state.head
        if rotated:
            state = TailState()
        fh.seek(state.offset)
        data = fh.read(MAX_CHUNK)
    parts = (state.pending + data).split(b"\n")
    decoded = [p.decode("utf-8", errors="replace").rstrip("\r") for p in parts[:-1]]
    lines = [ln for ln in decoded if ln.strip()]
    ties, seen = _tie_indexes(lines, state.seen)
    return TailResult(
        lines,
        TailState(state.offset + len(data), parts[-1], head, seen),
        rotated,
        ties,
    )
