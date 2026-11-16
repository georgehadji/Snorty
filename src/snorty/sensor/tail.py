from dataclasses import dataclass, field
from pathlib import Path

MAX_CHUNK = 8 * 1024 * 1024  # bytes read per call, so a huge backlog is never held in memory


@dataclass(frozen=True, slots=True)
class TailState:
    offset: int = 0  # bytes of the file consumed so far, including `pending`
    pending: bytes = b""  # trailing bytes of an unfinished line
    # The lines seen so far that carry the newest timestamp, with how often each appeared. Snort
    # stamps alerts to the microsecond, so two alerts can print as identical lines; this counts
    # them apart so neither is mistaken for a repeat of the other.
    stamp: str = ""
    seen: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class TailResult:
    lines: list[str]
    state: TailState
    rotated: bool
    # Per line: 0 for the first of its kind, then 1, 2, ...
    ties: list[int] = field(default_factory=list)


def _tie_indexes(
    lines: list[str], state: TailState
) -> tuple[list[int], str, tuple[tuple[str, int], ...]]:
    stamp, seen = state.stamp, dict(state.seen)
    ties: list[int] = []
    for line in lines:
        first = line.split(None, 1)[0]
        if first != stamp:
            stamp, seen = first, {}
        ties.append(seen.get(line, 0))
        seen[line] = ties[-1] + 1
    return ties, stamp, tuple(seen.items())


def read_new_lines(path: Path, state: TailState) -> TailResult:
    """Return the complete lines added since `state`, at most MAX_CHUNK bytes' worth.
    Call again until it returns no lines to read the rest.

    A file shorter than our offset counts as rotated or truncated and is re-read from 0.
    A rotated file that has already grown past the old offset is not detected (V1 limit).
    """
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return TailResult([], state, False)
    rotated = size < state.offset
    if rotated:
        state = TailState()
    with path.open("rb") as fh:
        fh.seek(state.offset)
        data = fh.read(MAX_CHUNK)
    parts = (state.pending + data).split(b"\n")
    decoded = [p.decode("utf-8", errors="replace").rstrip("\r") for p in parts[:-1]]
    lines = [ln for ln in decoded if ln.strip()]
    ties, stamp, seen = _tie_indexes(lines, state)
    return TailResult(
        lines,
        TailState(state.offset + len(data), parts[-1], stamp, seen),
        rotated,
        ties,
    )
