"""Snort's own packet-drop figure. Snort's alerts say nothing about drops, but its `perfmonitor`
preprocessor writes a CSV whose `pkt_drop_percent` column does. Snorty adds one marked line to
`snort.conf` for it and reads the newest row."""

import re
from pathlib import Path

FILE = "perfmon.csv"  # in Snort's log folder

MARK = "# snorty: perfmonitor (drop statistics); remove this line and the next to turn it off"
_HEAD, _TAIL = 8192, 16384  # bytes read: the header, and the newest rows


def perfmon_line(csv: Path, seconds: int = 60) -> str:
    return f"preprocessor perfmonitor: time {seconds} file {csv} pktcnt 1000"


def with_perfmon(conf: str, csv: Path) -> str:
    """`conf` with exactly one perfmonitor line of ours; the text is otherwise untouched."""
    eol = "\r\n" if "\r\n" in conf else "\n"
    block = f"{MARK}{eol}{perfmon_line(csv)}{eol}"
    if MARK in conf:
        return re.sub(
            rf"{re.escape(MARK)}[^\r\n]*\r?\n[^\r\n]*(\r?\n|$)", lambda _: block, conf, count=1
        )
    if conf and not conf.endswith("\n"):
        conf += eol
    return conf + block


def has_perfmon(conf: str) -> bool:
    return MARK in conf


def drop_column(head: str) -> int | None:
    """Which column of the rows is `pkt_drop_percent`, from the header line."""
    for line in head.splitlines():
        if line.startswith("#time,"):
            names = line[1:].split(",")
            return names.index("pkt_drop_percent") if "pkt_drop_percent" in names else None
    return None


def newest_drop_pct(tail: str, column: int) -> float | None:
    """`pkt_drop_percent` of the last complete data row, or None."""
    value: float | None = None
    for line in tail.splitlines():  # the first may be cut; the newest row never is
        if line and not line.startswith("#"):
            try:
                value = float(line.split(",")[column])
            except (IndexError, ValueError):
                continue
    return value


class DropReader:
    """Reads the perfmonitor file when it has changed since the last call."""

    def __init__(self, csv: Path) -> None:
        self._csv = csv
        self._seen: tuple[int, int] | None = None
        self._value: float | None = None

    def __call__(self) -> float | None:
        try:
            st = self._csv.stat()
            if self._seen == (st.st_mtime_ns, st.st_size):
                return self._value
            with self._csv.open("rb") as fh:
                head = fh.read(_HEAD)
                fh.seek(max(0, st.st_size - _TAIL))
                tail = fh.read()
        except OSError:
            return self._value
        self._seen = (st.st_mtime_ns, st.st_size)
        column = drop_column(head.decode("ascii", errors="replace"))
        if column is not None:
            self._value = newest_drop_pct(tail.decode("ascii", errors="replace"), column)
        return self._value
