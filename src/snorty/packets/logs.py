"""Snort's packet logs: which files can hold an alert's packet, and reading one for a time window.

Snort writes `snort.log.<start time>` next to the alert file, so the log for an alert is the
newest one that started at or before the alert. Reads are capped: a huge log is searched only as
far as the cap, and the result says when it was cut short.
"""

import re
from pathlib import Path

from snorty.packets.pcapfile import PcapFile, read_pcap

MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_CANDIDATES = 3  # an alert is in the newest log that predates it; a few more cover odd cases
_NAME = re.compile(r"snort\.log\.(\d{1,12})")


def candidate_logs(folder: Path, at_epoch: int) -> list[Path]:
    """Logs that started at or before `at_epoch` (seconds), newest first, at most a few."""
    found: list[tuple[int, Path]] = []
    try:
        entries = list(folder.iterdir())
    except OSError:
        return []
    for entry in entries:
        m = _NAME.fullmatch(entry.name)
        if m and int(m[1]) <= at_epoch and entry.is_file() and not entry.is_symlink():
            found.append((int(m[1]), entry))
    found.sort(key=lambda item: item[0], reverse=True)
    return [path for _, path in found[:MAX_CANDIDATES]]


def read_log(path: Path, window_ns: tuple[int, int]) -> PcapFile | None:
    """The frames of one log inside the time window; None if it is unreadable or not a pcap."""
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_LOG_BYTES + 1)
    except OSError:
        return None
    cut = len(data) > MAX_LOG_BYTES
    parsed = read_pcap(data[:MAX_LOG_BYTES], between=window_ns)
    if parsed is not None and cut:
        parsed = PcapFile(parsed.linktype, parsed.frames, True)
    return parsed
