from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class TailState:
    offset: int = 0  # bytes of the file consumed so far, including `pending`
    pending: bytes = b""  # trailing bytes of an unfinished line


@dataclass(frozen=True, slots=True)
class TailResult:
    lines: list[str]
    state: TailState
    rotated: bool


def read_new_lines(path: Path, state: TailState) -> TailResult:
    """Return the complete lines added since `state`.

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
        data = fh.read()
    parts = (state.pending + data).split(b"\n")
    lines = [p.decode("utf-8", errors="replace").rstrip("\r") for p in parts[:-1]]
    return TailResult(
        [ln for ln in lines if ln],
        TailState(state.offset + len(data), parts[-1]),
        rotated,
    )
